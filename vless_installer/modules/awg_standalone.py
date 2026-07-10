"""
vless_installer/modules/awg_standalone.py
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
    return importlib.import_module("vless_installer._core")


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

    # 1. Конфликт с chain Mode B (VLESS Ultimate Installer)
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


def awgs_install_dkms() -> bool:
    """
    Устанавливает amneziawg-tools + DKMS kernel module через PPA amnezia/ppa.
    Перенесено из bivlked install_amneziawg.sh (steps 1-2).

    Правильный PPA: amnezia/ppa (НЕ amnezia/awg)
    GPG fingerprint: 75C9DD72C799870E310542E24166F2C257290828
    DEB822 формат для Ubuntu 24.04+ и Debian 13+, legacy .list для Debian 12.
    """
    core = _core_module()
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
    # Ставим по одному пакету — если один упадёт, остальные всё равно установятся
    for pkg in ("curl", "qrencode", "wireguard-tools", "gpg", "dkms", "build-essential"):
        r = core._run(["apt-get", "install", "-y", pkg],
                      capture=True, check=False, quiet=True)
        if r.returncode != 0:
            core.log_to_file("WARN", f"apt install {pkg}: {r.stderr[-300:]}")

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
            # Если ошибка только на PPA Amnezia — продолжаем (issue #68 bivlked)
            stderr = r.stderr or ""
            if "amnezia" in stderr.lower():
                core.warn("PPA Amnezia временно недоступен — retry через 30 сек...")
                time.sleep(30)
                core._run(["apt-get", "update", "-y"], check=False, quiet=True)
            else:
                core.log_to_file("WARN", f"apt update: {stderr[-500:]}")

        # Проверяем, что пакет amneziawg-dkms появился в apt-cache
        r = core._run(["apt-cache", "show", "amneziawg-dkms"],
                      capture=True, check=False)
        if r.returncode != 0 or not r.stdout.strip():
            core.warn("Пакет amneziawg-dkms не найден в apt-cache после обновления PPA")
            core.warn(f"apt-cache stderr: {r.stderr[-300:] if r.stderr else '(пусто)'}")
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
            core.warn("→ Пробуем Go-версию (userspace) как fallback")
            return _awgs_install_dkms_fallback()
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_install_dkms exception: {e}")
        core.warn(f"Исключение при установке DKMS: {e}")
        return _awgs_install_dkms_fallback()

    # ── Шаг 3: проверка модуля ─────────────────────────────────────────────
    # modprobe amnezia (DKMS должен был собрать и загрузить модуль)
    core._run(["modprobe", "amnezia"], check=False, quiet=True)
    r = core._run(["lsmod"], capture=True, check=False)
    if "amnezia" not in r.stdout:
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
            return True
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_install_dkms_fallback: {e}")
    return False


# ============================================================================
#  ГЕНЕРАЦИЯ КЛЮЧЕЙ
# ============================================================================

def awgs_generate_keys() -> tuple:
    """
    Генерирует пару ключей сервера (priv+pub).
    Пробует `awg genkey`/`awg pubkey` (kernel-module версия), fallback на
    `wg genkey`/`wg pubkey` (из wireguard-tools).
    Ключи Curve25519 совместимы между WG и AWG.
    Если ни awg, ни wg не доступны — пытается доустановить wireguard-tools.
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
        if not wg_path:
            core.log_to_file("ERROR", "awgs_generate_keys: wg не установлен даже после apt install")
            return "", ""

    # ВАЖНО: prefer wg over awg для генерации ключей.
    # Причина: stub-обёртка awg (после fallback на amneziawg-go) проксирует
    # вызовы на amneziawg-go, который НЕ поддерживает genkey/pubkey/genpsk.
    # wg (из wireguard-tools) — нативный бинарник, всегда работает.
    bin_for_genkey = wg_path or awg_path
    if wg_path:
        core.info(f"Генерация ключей через wg ({wg_path})")
    else:
        core.info(f"Генерация ключей через awg ({awg_path}) — wg недоступен")

    # Приватный ключ (genkey читает /dev/urandom, не требует stdin, но подаём пустой)
    r = core._run([bin_for_genkey, "genkey"],
                  capture=True, check=False, input_text="")
    if r.returncode != 0:
        core.log_to_file("ERROR", f"{bin_for_genkey} genkey failed (rc={r.returncode}): {r.stderr}")
        return "", ""
    privkey = r.stdout.strip()

    if not privkey:
        core.log_to_file("ERROR", "awgs_generate_keys: пустой privkey")
        return "", ""

    # Публичный из приватного (pubkey читает privkey из stdin)
    r = core._run([bin_for_genkey, "pubkey"],
                  capture=True, check=False, input_text=privkey + "\n")
    if r.returncode != 0:
        core.log_to_file("ERROR", f"{bin_for_genkey} pubkey failed (rc={r.returncode}): {r.stderr}")
        return "", ""
    pubkey = r.stdout.strip()

    if not pubkey:
        core.log_to_file("ERROR", "awgs_generate_keys: пустой pubkey")
        return "", ""

    return privkey, pubkey


def awgs_generate_preshared_key() -> str:
    """
    Генерирует PresharedKey (опциональный, для per-client PSK).
    Prefer wg (нативный), fallback на awg.
    """
    core = _core_module()
    wg_path = core._run(["which", "wg"], capture=True, check=False).stdout.strip()
    awg_path = core._run(["which", AWGS_BIN], capture=True, check=False).stdout.strip()
    bin_for_genpsk = wg_path or awg_path
    if not bin_for_genpsk:
        return ""
    r = core._run([bin_for_genpsk, "genpsk"],
                  capture=True, check=False, input_text="")
    return r.stdout.strip() if r.returncode == 0 else ""


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
     "Доп. junk в transport-пакетах. 0 = выключено."),
    ("h1", "H1 (Init packet magic header)",
     0, 255, 1,
     "Magic header для init-пакета (0-255). "
     "Стандартные значения: H1=1, H2=2, H3=3, H4=4 (как в upstream)."),
    ("h2", "H2 (Response packet magic header)",
     0, 255, 2,
     "Magic header для response-пакета."),
    ("h3", "H3 (Under-load packet magic header)",
     0, 255, 3,
     "Magic header для under-load пакетов."),
    ("h4", "H4 (Transport packet magic header)",
     0, 255, 4,
     "Magic header для transport-пакетов."),
]

# I1-I5 — опциональные, hex-строки (не числа)
AWGS_PARAMS_SPEC_HEX = [
    # (key, label, recommended, description)
    ("i1", "I1 (Init packet junk allowed IP)",
     "random",
     "Hex-строка (48-64 hex chars = 24-32 байта). "
     "Опционально — оставьте пустым если не уверены. "
     "Tele2 Красноярск/Мегафон: ОСТАВИТЬ ПУСТЫМ (иначе блокировка). "
     "Введите 'auto' для случайной генерации, или hex вручную."),
    ("i2", "I2 (Response packet junk allowed IP)",
     "",
     "Опционально. Рекомендуется пустым."),
    ("i3", "I3 (Under-load packet junk allowed IP)",
     "",
     "Опционально. Рекомендуется пустым."),
    ("i4", "I4 (Transport packet junk allowed IP)",
     "",
     "Опционально. Рекомендуется пустым."),
    ("i5", "I5 (Transport packet junk IPv6 allowed IP)",
     "",
     "Опционально. Рекомендуется пустым."),
]


def awgs_prompt_custom_params() -> dict:
    """
    Интерактивный ввод всех параметров обфускации AWG 2.0.
    Для каждого параметра показывает: описание, диапазон, рекомендуемое значение.
    Пользователь может Enter (значение по умолчанию) или ввести своё.
    Возвращает dict с ключами jc/jmin/jmax/s1-s4/h1-h4/i1-i5.
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC, GREEN, YELLOW, DIM, BOLD = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM, core.BOLD
    )
    import random

    print()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom

    _box_top(f"Ручная настройка параметров обфускации AWG 2.0")
    _box_row()
    _box_row(f"  {DIM}Для каждого параметра укажите значение или Enter для рекомендуемого.{NC}")
    _box_row(f"  {DIM}Рекомендации основаны на тестах bivlked/amneziawg-installer.{NC}")
    _box_row()
    _box_bottom()
    print()

    params = {}

    # Числовые параметры
    for key, label, vmin, vmax, recommended, desc in AWGS_PARAMS_SPEC:
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

    # Hex-параметры (I1-I5)
    print(f"{BOLD}Опциональные параметры (I1-I5):{NC}")
    print(f"  {DIM}Оставьте пустым (Enter) если не уверены — большинство операторов не требуют.{NC}")
    print()
    for key, label, recommended, desc in AWGS_PARAMS_SPEC_HEX:
        print(f"{BOLD}{label}{NC}")
        print(f"  {DIM}{desc}{NC}")
        if recommended == "random":
            print(f"  {GREEN}Рекомендуется:{NC} auto (случайная генерация 24-32 байта)")
        elif recommended:
            print(f"  {GREEN}Рекомендуется:{NC} {recommended}")
        else:
            print(f"  {GREEN}Рекомендуется:{NC} пусто")
        val = input(f"  {CYAN}Значение (Enter=пусто, 'auto'=случайный): {NC}").strip()
        if val.lower() == "auto":
            # Генерируем случайный hex 28 байт (56 hex chars)
            i1_len = random.randint(24, 32)
            val = "".join(random.choices("0123456789abcdef", k=i1_len * 2))
            info(f"  Сгенерирован {key}: {val[:32]}...")
        elif val and not all(c in "0123456789abcdefABCDEF" for c in val):
            warn(f"  '{val}' не hex — игнорирую (оставляю пустым)")
            val = ""
        params[key] = val
        print()

    # Итоговая сводка
    _box_top(f"Итоговые параметры")
    _box_row()
    for key, label, _, _, _, _ in AWGS_PARAMS_SPEC:
        _box_row(f"  {CYAN}{key.upper():<6}{NC} = {params[key]}")
    for key, label, _, _ in AWGS_PARAMS_SPEC_HEX:
        val = params[key]
        if val:
            _box_row(f"  {CYAN}{key.upper():<6}{NC} = {val[:40]}{'...' if len(val) > 40 else ''}")
        else:
            _box_row(f"  {CYAN}{key.upper():<6}{NC} = {DIM}(пусто){NC}")
    _box_bottom()

    # Валидация
    ok, err = awgs_presets_validate_params(params)
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
) -> str:
    """
    Генерирует содержимое awg0.conf (серверная сторона).
    """
    peers = peers or []

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
    if params.get("i1"):
        lines.append(f"I1 = {params['i1']}")
    if params.get("i2"):
        lines.append(f"I2 = {params['i2']}")
    if params.get("i3"):
        lines.append(f"I3 = {params['i3']}")
    if params.get("i4"):
        lines.append(f"I4 = {params['i4']}")
    if params.get("i5"):
        lines.append(f"I5 = {params['i5']}")

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
    """
    core = _core_module()
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
    vless_installer.modules.awg_net_common — тот же слой использует
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
    info("Создание systemd-юнита awg-nat.service (idempotent ExecStart)...")
    from .awg_constants import AWGS_SYSTEMD_AWG_QUICK
    nat_unit = Path("/etc/systemd/system/awg-nat.service")
    # Bash-сниппет: определяем $WAN, затем идемпотентно добавляем правила.
    exec_start_body = (
        "WAN=$(ip route show default | awk '{print $5; exit}'); "
        + build_nat_idempotent_shell(awg_subnet, AWGS_INTERFACE, "$WAN")
    )
    exec_stop_body = (
        "WAN=$(ip route show default | awk '{print $5; exit}'); "
        + build_nat_cleanup_shell(awg_subnet, AWGS_INTERFACE, "$WAN")
    )
    nat_unit_content = f"""[Unit]
Description=AWG standalone NAT + FORWARD rules (idempotent)
After={AWGS_SYSTEMD_AWG_QUICK}
Requires={AWGS_SYSTEMD_AWG_QUICK}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '{exec_start_body}'
ExecStop=/bin/bash -c '{exec_stop_body}'

[Install]
WantedBy=multi-user.target
"""
    try:
        nat_unit.write_text(nat_unit_content)
        core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
        core._run(["systemctl", "enable", "awg-nat.service"],
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
) -> bool:
    """
    Полный цикл установки standalone AWG.
    Возвращает True при успехе.
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    GREEN, NC, CYAN, BOLD = core.GREEN, core.NC, core.CYAN, core.BOLD

    _box_top(f"Установка AmneziaWG 2.0 (standalone)")
    _box_row()
    _box_bottom()

    # 1. Валидация
    if port < AWGS_PORT_MIN or port > AWGS_PORT_MAX:
        warn(f"Порт {port} вне диапазона ({AWGS_PORT_MIN}-{AWGS_PORT_MAX})")
        return False
    # Если переданы custom_params — валидируем их, иначе проверяем пресет
    if custom_params:
        ok, err = awgs_presets_validate_params(custom_params)
        if not ok:
            warn(f"Пользовательские параметры: {err}")
            return False
    else:
        ok, err = awgs_presets_validate_params(awgs_presets_generate(carrier_preset))
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

    # 8. Параметры обфускации
    if custom_params:
        info("Используются пользовательские параметры обфускации...")
        params = custom_params
        info(f"  Jc={params['jc']}, Jmin={params['jmin']}, Jmax={params['jmax']}, "
             f"S1={params['s1']}, S2={params['s2']}, S3={params['s3']}, S4={params['s4']}, "
             f"H1={params['h1']}, H2={params['h2']}, H3={params['h3']}, H4={params['h4']}")
        if params.get("i1"):
            info(f"  I1={'задан' if params['i1'] else 'отсутствует'}")
    else:
        info(f"Генерация параметров обфускации (preset: {carrier_preset})...")
        params = awgs_presets_generate(carrier_preset)
        preset_info = awgs_presets_get(carrier_preset)
        if preset_info:
            info(f"  Пресет: {preset_info['label']}")
        info(f"  Jc={params['jc']}, Jmin={params['jmin']}, Jmax={params['jmax']}, "
             f"I1={'задан' if params['i1'] else 'отсутствует'}")

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
        warn("Не удалось запустить сервис — проверьте journalctl")
        # Не возвращаем False — конфиг создан, можно дебажить

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
    )

    # 13. Создание cron для --expires (если ещё нет)
    awgs_setup_expires_cron()

    success("Установка AmneziaWG 2.0 завершена!")
    print()
    _box_top(f"Готово")
    _box_row(f"  {GREEN}Интерфейс:{NC}        {AWGS_INTERFACE}")
    _box_row(f"  {GREEN}UDP-порт:{NC}         {port}")
    _box_row(f"  {GREEN}Подсеть:{NC}           {subnet}")
    if allow_ipv6_tunnel:
        _box_row(f"  {GREEN}IPv6 подсеть:{NC}     {subnet_v6}")
    _box_row(f"  {GREEN}Пресет:{NC}            {carrier_preset}")
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
    """Создаёт cron-задачу для автоудаления истёкших клиентов."""
    from .awg_constants import AWGS_CRON_EXPIRES
    cron_content = (
        "# AWG standalone: автоудаление истёкших клиентов\n"
        "*/5 * * * * root /usr/bin/python3 -c "
        "\"from vless_installer.modules.awg_expires import awgs_expires_check; awgs_expires_check()\" "
        f">> {AWGS_LOG_FILE} 2>&1\n"
    )
    try:
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
        _box_top(f"AmneziaWG 2.0 (standalone VPN)")
        _box_row()

        # Статус установки
        installed = awgs_state_is_installed()
        if installed:
            st = awgs_state_load()
            _box_row(f"  {GREEN}● Установлен{NC}  (порт {st.get('port', '?')}, "
                     f"пиры: {len(st.get('peers', []))})")
        else:
            _box_row(f"  {YELLOW}○ Не установлен{NC}")
        _box_row()
        _box_item("1", f"Установить standalone AWG")
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


def _awgs_menu_install() -> None:
    """Подменю установки standalone AWG."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    CYAN, NC, GREEN, DIM = core.CYAN, core.NC, core.GREEN, core.DIM

    print()
    _box_top(f"Установка AmneziaWG 2.0")
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
    _box_desc("Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 — каждый параметр вручную с рекомендациями.")
    _box_item("Q", f"Назад")
    _box_bottom()
    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

    if ch == "1":
        awgs_install(carrier_preset="default")
    elif ch == "2":
        awgs_install(carrier_preset="mobile")
    elif ch == "3":
        _awgs_menu_carrier()
    elif ch == "4":
        _awgs_menu_advanced()
    elif ch == "5":
        _awgs_menu_custom_params()
    elif ch in ("q", ""):
        return


def _awgs_menu_custom_params() -> None:
    """Подменю ручной настройки параметров обфускации."""
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

    # Теперь — параметры обфускации
    custom_params = awgs_prompt_custom_params()
    if custom_params is None:
        warn("Параметры не валидны — отмена")
        return

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
    )


def _awgs_menu_carrier() -> None:
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
            awgs_install(carrier_preset=presets[idx])
    except ValueError:
        pass


def _awgs_menu_advanced() -> None:
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
      2. Обновляем state["params"] через awgs_state_update
      3. Перестраиваем awg0.conf через awg_peer_rebuild_conf(apply=True)
         — он вызывает awgs_apply() с syncconf (без даунтайма)

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

    # Проверяем что AWG установлен
    if not awgs_state_is_installed():
        return False, "Standalone AWG не установлен"

    state = awgs_state_load()

    # Определяем пресет для генерации
    if not preset_name:
        preset_name = state.get("carrier_preset", "default")
    if preset_name not in awgs_presets_list():
        return False, f"Неизвестный пресет: {preset_name}"

    info(f"Ротация параметров обфускации (пресет: {preset_name})...")

    # Генерируем новые параметры
    try:
        new_params = awgs_presets_generate(preset_name)
    except ValueError as e:
        return False, str(e)

    # Сохраняем в state
    awgs_state_update(params=new_params)

    # Перестраиваем конфиг и применяем через syncconf (без даунтайма)
    info("Применение через awg syncconf (без разрыва туннеля)...")
    if awg_peer_rebuild_conf(apply=True):
        i1_display = new_params.get("i1", "")[:16] + "..." if new_params.get("i1") else "отсутствует"
        msg = (f"Параметры обновлены: Jc={new_params['jc']} "
               f"Jmin={new_params['jmin']} Jmax={new_params['jmax']} "
               f"I1={i1_display}")
        success(msg)
        core.log_to_file("INFO", f"awgs_rotate_obfuscation: {msg}")
        return True, msg
    else:
        warn("syncconf не удался — применён restart (кратковременный разрыв)")
        return False, "syncconf не удался, применён restart"


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
        i1_display = i1[:16] + "..." if i1 else "отсутствует"
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
