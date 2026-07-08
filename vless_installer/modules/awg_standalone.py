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


def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  КОНФЛИКТ-ЧЕК
# ============================================================================

def awgs_check_conflicts(port: int = AWGS_DEFAULT_PORT) -> list:
    """
    Проверяет конфликты перед установкой standalone AWG.
    Возвращает список строк-конфликтов (пустой = установка безопасна).
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

    # 3. Конфликт порта
    r = core._run(["ss", "-ulnp"], capture=True, check=False)
    if r.returncode == 0 and f":{port} " in r.stdout:
        conflicts.append(
            f"UDP-порт {port} уже занят. Укажите другой --port "
            f"(доступные: 51820-51830, 11100 не использовать — занят chain)."
        )

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
    Устанавливает amneziawg-tools + DKMS kernel module.
    Ubuntu: PPA amneziawg (нужен GPG-ключ)
    Debian: PPA amneziawg через маппинг codename на focal/noble
    """
    core = _core_module()
    info = awgs_detect_os()
    distro = info["distro"].lower()
    codename = info["codename"].lower() or info["version"]

    core.info(f"ОС: {distro} {info['version']} ({codename})")

    # Устанавливаем зависимости для сборки DKMS
    core.info("Установка зависимостей для DKMS-сборки...")
    deps = ["dkms", "linux-headers-generic", "build-essential", "curl", "qrencode"]
    if distro == "debian":
        deps = ["dkms", "linux-headers-amd64", "build-essential", "curl", "qrencode"]
    core._run(["apt-get", "update", "-y"], check=False, quiet=True)
    r = core._run(["apt-get", "install", "-y"] + deps, capture=True, check=False)
    if r.returncode != 0:
        core.log_to_file("WARN", f"apt install deps: {r.stderr[-500:]}")

    # PPA для Ubuntu/Debian
    ppa_mapping = {
        # Debian
        "bookworm": "focal",
        "trixie":   "noble",
        # Ubuntu
        "focal":    "focal",
        "jammy":    "jammy",
        "noble":    "noble",
        "oracular": "noble",   # fallback
        "plucky":   "noble",   # fallback
    }
    ppa_codename = ppa_mapping.get(codename, "noble")
    core.info(f"PPA codename: {ppa_codename} (маппинг из {codename})")

    # Добавляем PPA amneziawg
    ppa_line = f"deb https://ppa.launchpadcontent.net/amnezia/awg/ubuntu {ppa_codename} main"
    sources_list = Path("/etc/apt/sources.list.d/amneziawg.list")

    # Сначала пробуем DEB822 формат (Debian 13+)
    deb822_file = Path("/etc/apt/sources.list.d/amneziawg.sources")
    try:
        if not sources_list.exists() and not deb822_file.exists():
            sources_list.write_text(ppa_line + "\n")
        # GPG-ключ
        core._run(
            ["bash", "-c",
             "curl -fsSL https://ppa.launchpadcontent.net/amnezia/awg/ubuntu/gpg "
             "| gpg --dearmor -o /etc/apt/trusted.gpg.d/amneziawg.gpg"],
            check=False, quiet=True,
        )
        # apt update с PPA
        r = core._run(["apt-get", "update", "-y"], capture=True, check=False)
        if r.returncode != 0:
            core.log_to_file("WARN", f"apt update after PPA: {r.stderr[-500:]}")

        # Устанавливаем amneziawg + dkms module
        r = core._run(
            ["apt-get", "install", "-y", "amneziawg-tools", "amneziawg-dkms"],
            capture=True, check=False, timeout=300,
        )
        if r.returncode != 0:
            core.log_to_file("ERROR", f"apt install amneziawg: {r.stderr[-1000:]}")
            core.warn("Установка из PPA не удалась — пробуем альтернативный путь")
            return _awgs_install_dkms_fallback()
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_install_dkms: {e}")
        return _awgs_install_dkms_fallback()

    # Проверяем, что модуль загрузился
    core._run(["modprobe", "amnezia"], check=False, quiet=True)
    r = core._run(["lsmod"], capture=True, check=False)
    if "amnezia" not in r.stdout:
        core.warn("DKMS-модуль amnezia не загрузился — проверьте лог")
        return False

    # Проверяем бинарники
    for binary in (AWGS_BIN, AWGS_QUICK_BIN):
        r = core._run(["which", binary], capture=True, check=False)
        if r.returncode != 0:
            core.warn(f"Бинарник {binary} не найден после установки")
            return False

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
    Генерирует пару ключей сервера (priv+pub) через `awg genkey` / `awg pubkey`.
    Возвращает (privkey, pubkey) или ("", "") при ошибке.
    """
    core = _core_module()
    # Приватный ключ
    r = core._run(["bash", "-c", f"{AWGS_BIN} genkey"], capture=True, check=False)
    if r.returncode != 0:
        core.log_to_file("ERROR", f"awg genkey: {r.stderr}")
        return "", ""
    privkey = r.stdout.strip()
    # Публичный из приватного
    r = core._run(["bash", "-c", f"echo '{privkey}' | {AWGS_BIN} pubkey"],
                  capture=True, check=False)
    if r.returncode != 0:
        core.log_to_file("ERROR", f"awg pubkey: {r.stderr}")
        return "", ""
    pubkey = r.stdout.strip()
    return privkey, pubkey


def awgs_generate_preshared_key() -> str:
    """Генерирует PresharedKey (опциональный, для per-client PSK)."""
    core = _core_module()
    r = core._run(["bash", "-c", f"{AWGS_BIN} genpsk"], capture=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


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

    # Серверный IP в подсети (первый адрес)
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    server_ip = f"{base}.1/32"
    # IPv6 сервера
    v6_base = subnet_v6.split("::")[0]
    server_ipv6 = f"{v6_base}::1/128"

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
                  capture=True, check=False, timeout=30)
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
              check=False, quiet=True, timeout=30)
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

    # 8. Параметры обфускации (по пресету)
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
    _box_item("3", f"Выбрать оператора вручную (8 пресетов)")
    _box_desc("Yota MSK, Tele2 MSK/Krasnoyarsk, Таттелеком, Мегафон, Билайн, T-Mobile US")
    _box_item("4", f"Расширенные параметры (порт, подсеть, MTU, IPv6, endpoint)")
    _box_desc("Тонкая настройка под конкретный сервер.")
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
    elif ch in ("q", ""):
        return


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
