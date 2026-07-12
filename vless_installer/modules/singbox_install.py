"""
vless_installer/modules/singbox_install.py
───────────────────────────────────────────────────────────────────────────────
Установка бинарника sing-box и systemd-юнита.

По образцу hysteria2_exit_mgr.py::_install_h2_binary:
  1. Получение tag_name + asset URL через GitHub API
  2. Скачивание через fetch_package(SINGBOX_SPEC, ...)
  3. Проверка --version
  4. Создание systemd-юнита /etc/systemd/system/sing-box.service
  5. mkdir /etc/sing-box, /var/lib/sing-box

НЕ затрагивает config.json (это делает singbox_config.py).
НЕ запускает сервис — только enable. Запуск — после генерации конфига.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from vless_installer.modules.singbox_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _systemctl, _service_active, _service_enabled,
    _singbox_binary_exists, _singbox_binary_version,
    _detect_arch, _get_latest_release_info,
    _is_port_free, _who_owns_port,
    SINGBOX_BINARY, SINGBOX_CONFIG_DIR, SINGBOX_CONFIG_FILE,
    SINGBOX_LOG_FILE, SINGBOX_SERVICE,
)
from vless_installer.modules.singbox_packages import SINGBOX_SPEC
from vless_installer.modules.singbox_state import (
    singbox_state_init, singbox_state_load, singbox_state_save,
    singbox_state_is_installed, singbox_state_get_version,
)
from vless_installer.modules.download_manager import fetch_package


# ============================================================================
#  Systemd unit
# ============================================================================
_SYSTEMD_UNIT = """\
[Unit]
Description=sing-box (VLESS Ultimate Installer)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} run -c {config}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
StandardOutput=append:{log}
StandardError=append:{log}
# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/sing-box /var/lib/sing-box /var/log
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
"""


def _install_systemd_unit() -> bool:
    """Создаёт /etc/systemd/system/sing-box.service."""
    unit_text = _SYSTEMD_UNIT.format(
        binary=SINGBOX_BINARY,
        config=SINGBOX_CONFIG_FILE,
        log=SINGBOX_LOG_FILE,
    )
    unit_path = Path(f"/etc/systemd/system/{SINGBOX_SERVICE}.service")
    try:
        unit_path.write_text(unit_text)
        _run(["systemctl", "daemon-reload"], quiet=True)
        _run(["systemctl", "enable", SINGBOX_SERVICE], quiet=True)
        return True
    except Exception as e:
        error(f"Не удалось создать {SINGBOX_SERVICE}.service: {e}")
        return False


def _uninstall_systemd_unit() -> bool:
    """Останавливает и удаляет systemd-юнит."""
    _run(["systemctl", "stop", SINGBOX_SERVICE], quiet=True)
    _run(["systemctl", "disable", SINGBOX_SERVICE], quiet=True)
    unit_path = Path(f"/etc/systemd/system/{SINGBOX_SERVICE}.service")
    try:
        if unit_path.exists():
            unit_path.unlink()
        _run(["systemctl", "daemon-reload"], quiet=True)
        return True
    except Exception:
        return False


# ============================================================================
#  Установка бинарника
# ============================================================================
def singbox_install_binary(force: bool = False) -> bool:
    """
    Скачивает и устанавливает sing-box бинарник.

    Шаги:
      1. Если бинарник уже есть и не force — проверяем --version, выходим OK
      2. Получаем latest tag + tarball filename через GitHub API
      3. fetch_package(SINGBOX_SPEC, tag=..., tarball_filename=...) —
         перебор зеркал
      4. Проверка --version
      5. Создание systemd-юнита
      6. mkdir /etc/sing-box, /var/lib/sing-box, /etc/sing-box/certs
      7. State init

    Returns:
      True при успехе, False при провале.
    """
    # 1. Уже установлен?
    if _singbox_binary_exists() and not force:
        ver = _singbox_binary_version()
        if ver:
            info(f"sing-box уже установлен: v{ver}")
            if not singbox_state_is_installed():
                # Бинарник есть, state нет — инициализируем
                singbox_state_init(version=ver)
                _install_systemd_unit()
            return True

    # 2. Получаем latest release
    info("Получаю информацию о последнем релизе sing-box с GitHub API...")
    tag, tarball = _get_latest_release_info()
    if not tag or not tarball:
        error("Не удалось получить информацию о релизе sing-box")
        warn("Проверьте интернет-соединение или скачайте бинарник вручную:")
        warn(f"  /root/{tarball or 'sing-box-X.Y.Z-linux-amd64.tar.gz'}")
        return False

    info(f"Последняя версия: {tag}, файл: {tarball}")

    # 3. Скачивание через fetch_package
    arch = _detect_arch()
    info(f"Архитектура: {arch}")
    ok = fetch_package(
        SINGBOX_SPEC,
        tag=tag,
        tarball_filename=tarball,
    )
    if not ok:
        error("Не удалось скачать sing-box ни с одного зеркала")
        return False

    # 4. Проверка версии
    if not _singbox_binary_exists():
        error("Бинарник не обнаружен после установки")
        return False

    ver = _singbox_binary_version()
    if not ver:
        warn("Бинарник установлен, но не отвечает на --version (возможно, неверная архитектура)")
    else:
        success(f"sing-box установлен: v{ver}")

    # 5. Systemd-юнит
    if not _install_systemd_unit():
        return False

    # 6. Директории
    SINGBOX_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    (SINGBOX_CONFIG_DIR / "certs").mkdir(parents=True, exist_ok=True)
    Path("/var/lib/sing-box").mkdir(parents=True, exist_ok=True)
    SINGBOX_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    # 7. State init
    singbox_state_init(version=ver or tag)

    success("sing-box backend готов к настройке протоколов")
    log_to_file("INFO", f"sing-box installed v{ver or tag}")
    return True


def singbox_uninstall_binary() -> bool:
    """Полное удаление sing-box: сервис + бинарник + конфиг + state."""
    # 1. Останавливаем сервис
    _uninstall_systemd_unit()

    # 2. Удаляем бинарник
    if SINGBOX_BINARY.exists():
        try:
            SINGBOX_BINARY.unlink()
            info(f"Удалён {SINGBOX_BINARY}")
        except Exception as e:
            warn(f"Не удалось удалить {SINGBOX_BINARY}: {e}")

    # 3. Удаляем конфиг и сертификаты
    if SINGBOX_CONFIG_DIR.exists():
        import shutil
        try:
            shutil.rmtree(SINGBOX_CONFIG_DIR)
            info(f"Удалён {SINGBOX_CONFIG_DIR}")
        except Exception as e:
            warn(f"Не удалось удалить {SINGBOX_CONFIG_DIR}: {e}")

    # 4. State
    from vless_installer.modules.singbox_state import singbox_state_delete
    singbox_state_delete()
    info("sing-box state удалён")

    success("sing-box полностью удалён")
    log_to_file("INFO", "sing-box uninstalled")
    return True


# ============================================================================
#  Старт/стоп/рестарт сервиса
# ============================================================================
def _preflight_port_check() -> Optional[str]:
    """Pre-flight проверка listen-портов из config.json.

    Возвращает None если все порты свободны, иначе строку с описанием
    конфликта (для печати через error()).

    Решает проблему crash-loop из 100+ рестартов systemd: sing-box пытается
    bind() на занятый порт, падает с EADDRINUSE, systemd рестартует — цикл.
    Ловим ошибку ДО systemctl restart, чтобы:
      • пользователь сразу видел занятый pid и inbound
      • не плодились 100+ рестартов в journalctl
      • не было ложного success() в вызывающем коде
    """
    if not SINGBOX_CONFIG_FILE.exists():
        return None  # конфига нет — singbox_start() и так ругнётся

    try:
        cfg = json.loads(SINGBOX_CONFIG_FILE.read_text())
    except Exception:
        return None  # невалидный JSON — sing-box check поймает

    inbounds = cfg.get("inbounds", []) or []
    if not inbounds:
        return None

    conflicts = []
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        port = ib.get("listen_port")
        if not isinstance(port, int) or port == 0:
            continue  # 0 = только через detour, не bind'ится
        listen = ib.get("listen", "0.0.0.0")
        # Определяем протокол: TUIC/Hysteria/Hysteria2 — UDP, остальные TCP
        ib_type = ib.get("type", "")
        proto = "udp" if ib_type in ("tuic", "hysteria", "hysteria2") else "tcp"

        if _is_port_free(port, listen, proto=proto):
            continue

        who = _who_owns_port(port, listen, proto=proto)
        tag = ib.get("tag", ib_type or "?")
        who_str = f" — занят {who}" if who else " — занят"
        conflicts.append(
            f"  • {proto.upper()} {listen}:{port} (inbound '{tag}'){who_str}"
        )

    if conflicts:
        return (
            "listen-порты sing-box заняты — сервис не сможет запуститься:\n"
            + "\n".join(conflicts)
            + "\nОсвободите порт (stop процесса / смените listen_port) и повторите."
        )
    return None


def singbox_start() -> bool:
    """Запускает сервис sing-box. Возвращает True если активен."""
    if not _singbox_binary_exists():
        error("Бинарник sing-box не установлен")
        return False
    if not SINGBOX_CONFIG_FILE.exists():
        error(f"Конфиг не найден: {SINGBOX_CONFIG_FILE}")
        return False

    # Тест конфига перед стартом
    r = _run([str(SINGBOX_BINARY), "check", "-c", str(SINGBOX_CONFIG_FILE)],
             capture=True, quiet=True)
    if r.returncode != 0:
        error("Конфиг sing-box невалиден:")
        error((r.stdout + r.stderr)[:400])
        return False

    # Pre-flight port-check: ловим EADDRINUSE ДО systemctl restart,
    # иначе systemd уходит в crash-loop из 100+ рестартов (restart=on-failure,
    # RestartSec=5 — пока пользователь читает лог, счётчик улетает за 100).
    conflict = _preflight_port_check()
    if conflict:
        error(conflict)
        return False

    if not _systemctl("restart"):
        error("Не удалось запустить sing-box")
        _run(["journalctl", "-u", SINGBOX_SERVICE, "-n", "20",
              "--no-pager"], quiet=False)
        return False
    time.sleep(2)

    if not _service_active():
        error(f"{SINGBOX_SERVICE} упал после старта")
        _run(["journalctl", "-u", SINGBOX_SERVICE, "-n", "20",
              "--no-pager"], quiet=False)
        return False

    success("sing-box запущен")
    return True


def singbox_stop() -> bool:
    return _systemctl("stop")


def singbox_restart() -> bool:
    return singbox_start()  # check + restart


def singbox_reload() -> bool:
    """Soft-reload через systemd reload (если поддерживается)."""
    return _systemctl("reload")


def singbox_status() -> dict:
    """Возвращает dict с состоянием sing-box."""
    return {
        "binary_installed":  _singbox_binary_exists(),
        "binary_version":    _singbox_binary_version(),
        "config_exists":     SINGBOX_CONFIG_FILE.exists(),
        "service_active":    _service_active(),
        "service_enabled":   _service_enabled(),
        "state_installed":   singbox_state_is_installed(),
        "state_version":     singbox_state_get_version(),
        "enabled_protocols": [],  # заполнить вызывающим кодом через singbox_state
    }
