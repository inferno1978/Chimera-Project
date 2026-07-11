"""
vless_installer/modules/slipgate_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для SlipGate install.sh — официального установочного скрипта.

Используется slipgate.py для скачивания install.sh и его запуска через bash.
До миграции slipgate.py делал это через `curl -fsSL | sudo bash` — пайп в
bash, без сохранения на диск, без зеркал.

Особенности:
  • Скачанный файл — bash-скрипт.
  • post_install: copy2 в install_dests[0]/install.sh + chmod 0o755.
  • Вызывающий код запускает `bash {install_dests[0]}/install.sh` после
    успешного fetch_package.
  • install.sh ВНУТРИ себя качает slipgate binary — эти внутренние загрузки
    остаются вне контроля Python (это ограничение подхода fetch_package;
    полностью проконтролировать можно только переписав install.sh на Python).

install_dests = [/tmp] — куда сохраняется скрипт (временное размещение
для запуска; скрипт сам решает куда ставить slipgate binary).
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from vless_installer.modules.slipgate_packages import SLIPGATE_INSTALLER_SPEC
"""
from __future__ import annotations

import shutil
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.slipgate_mirrors import get_slipgate_installer_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# install.sh сохраняется во /tmp для запуска. Скрипт сам ставит slipgate
# binary в /usr/local/bin/slipgate — это НЕ install_dest этого spec'а.
_SLIPGATE_INSTALL_DESTS: list[Path] = [Path("/tmp")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "slipgate-install.sh".
# НЕ "install.sh" чтобы избежать конфликта с другими скриптами в /tmp.
_SLIPGATE_DEST_FILENAME = "slipgate-install.sh"

# Минимальный размер install.sh.
# Реальный размер: ~10-20 KB (bash скрипт).
# 500 байт — нижний порог, отлавливает HTML-страницы 404.
_MIN_INSTALLER_SIZE = 500


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _slipgate_installer_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для install.sh через slipgate_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (install.sh).
    """
    return get_slipgate_installer_mirrors()


# ============================================================================
#  post_install — copy2 install.sh + chmod 0o755
# ============================================================================
def _post_install_slipgate(src: Path, install_dests: list[Path]) -> bool:
    """Копирует install.sh в install_dests[0]/slipgate-install.sh.

    Простой copy2 + chmod 0o755. Скрипт запускается вызывающим кодом через
    `bash {dest}` после успешного fetch_package.
    """
    if not install_dests:
        return False
    dest_dir = install_dests[0]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / _SLIPGATE_DEST_FILENAME
    try:
        shutil.copy2(str(src), str(dest))
        dest.chmod(0o755)
        return True
    except Exception:
        return False


# ============================================================================
#  PackageSpec — SlipGate install.sh
# ============================================================================
SLIPGATE_INSTALLER_SPEC = PackageSpec(
    name="SlipGate install.sh",
    filename_builder=lambda **kw: "install.sh",
    mirror_urls_builder=_slipgate_installer_mirror_urls,
    install_dests=_SLIPGATE_INSTALL_DESTS,       # [/tmp]
    manual_incoming_dir=_MANUAL_DIR,             # /root/
    min_size=_MIN_INSTALLER_SIZE,                # 500 байт
    post_install=_post_install_slipgate,         # copy2 + chmod 0o755
)
