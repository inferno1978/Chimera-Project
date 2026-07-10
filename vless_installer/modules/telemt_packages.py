"""
vless_installer/modules/telemt_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec-инстансы для бинарников telemt и telemt-panel.

Два spec'а с РАЗНЫМИ owner/repo:
  • TELEMT_SPEC       — owner="telemt",       repo="telemt"
  • TELEMT_PANEL_SPEC — owner="amirotin",     repo="telemt_panel"

Это убирает дублирование из telemt_mirrors.py где _gh_proxy_telemt/
_gh_proxy_panel/_jsdelivr_telemt/_jsdelivr_panel были копиями друг друга
с разницей только в owner/repo. Теперь — два вызова build_mirror_urls()
с разными параметрами.

АРХИТЕКТУРНАЯ ЗАЩИТА ОТ БАГА 21d7baf:
  PackageSpec.__post_init__ assert гарантирует manual_incoming_dir (/root/)
  != install_dests (/tmp/telemt_packages). Файл в install_dests (от
  предыдущего запуска) НЕ блокирует повторное сетевое скачивание.

УБРАНА ЗАВИСИМОСТЬ ОТ api.github.com:
  Раньше _get_latest_release() шёл в api.github.com за tag_name. При
  блокировке возвращал ('', '') и установка тихо проваливалась.
  Теперь tag="latest" в build_mirror_urls() — release_github_url()
  генерирует releases/latest/download/{filename}, GitHub сам делает
  HTTP-редирект на нужный тег. api.github.com не нужен вообще.

Точки входа:
    from vless_installer.modules.telemt_packages import (
        TELEMT_SPEC, TELEMT_PANEL_SPEC,
    )
"""
from __future__ import annotations

import shutil
import tarfile
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.github_mirrors import build_mirror_urls
from vless_installer.modules.telemt_mirrors import detect_arch_libc


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================
_TELEMT_BIN       = Path("/usr/local/bin/telemt")
_TELEMT_PANEL_BIN = Path("/usr/local/bin/telemt-panel")

# Временная директория для install_dests — post_install делает реальную
# установку (extract + copy2 в BIN_PATH), а не copy2 в install_dests.
# /root/ НЕ должен совпадать с этим путём — PackageSpec инвариант.
_INSTALL_TMP = Path("/tmp/telemt_packages")

# manual_incoming_dir — ТОЛЬКО /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")


# ============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ: lazy import (избегает циклического импорта)
# ============================================================================
def _get_mtproto_module():
    """Ленивый импорт mtproto.py — для _run, цветов."""
    import importlib
    return importlib.import_module("vless_installer.modules.mtproto")


def _get_panel_module():
    """Ленивый импорт telemt_panel.py — для _run, цветов."""
    import importlib
    return importlib.import_module("vless_installer.modules.telemt_panel")


# ============================================================================
#  post_install — extract tar.gz + copy2 в BIN_PATH + chmod 755
# ============================================================================
def _post_install_telemt(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает tar.gz, находит бинарник telemt, копирует в BIN_PATH.

    src = скачанный tar.gz архив.
    install_dests — игнорируется (бинарник ставится в _TELEMT_BIN).
    """
    mtproto = _get_mtproto_module()
    _ok = mtproto._ok
    _err = mtproto._err

    tmp = Path(tempfile.mkdtemp())
    try:
        with tarfile.open(src) as tf:
            tf.extractall(tmp)
        found = list(tmp.rglob("telemt"))
        if not found:
            _err("Бинарник не найден в архиве")
            return False
        shutil.copy2(str(found[0]), str(_TELEMT_BIN))
        _TELEMT_BIN.chmod(0o755)
        _ok(f"Установлено: {_TELEMT_BIN}")
        return True
    except Exception as e:
        _err(f"Ошибка: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _post_install_panel(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает tar.gz, находит бинарник telemt-panel, копирует в BIN_PATH.

    Атомарная замена через staging + os.replace (как в старом коде) —
    чтобы не упать с "Text file busy" если сервис активен.
    """
    import os
    panel = _get_panel_module()
    _ok = panel._ok
    _err = panel._err

    BIN_PATH = _TELEMT_PANEL_BIN
    tmp = Path(tempfile.mkdtemp())
    try:
        with tarfile.open(src) as tf:
            tf.extractall(tmp)
        found = [p for p in tmp.rglob("telemt-panel-*-linux") if p.is_file()]
        if not found:
            _err("Бинарник не найден в архиве")
            return False
        # Атомарная замена: staging + os.replace
        staging = BIN_PATH.parent / f".{BIN_PATH.name}.new"
        shutil.copy2(str(found[0]), str(staging))
        staging.chmod(0o755)
        os.replace(str(staging), str(BIN_PATH))
        _ok(f"Установлено: {BIN_PATH}")
        return True
    except Exception as e:
        _err(f"Ошибка: {e}")
        staging = BIN_PATH.parent / f".{BIN_PATH.name}.new"
        staging.unlink(missing_ok=True)
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — telemt (MTProxy-сервер)
# ============================================================================
TELEMT_SPEC = PackageSpec(
    name="telemt",
    filename_builder=lambda: f"telemt-{detect_arch_libc()[0]}-linux-{detect_arch_libc()[1]}.tar.gz",
    mirror_urls_builder=lambda filename: build_mirror_urls(
        owner="telemt",
        repo="telemt",
        filename=filename,
        tag="latest",
        jsdelivr_hosts=(),           # jsDelivr не работает с release-assets
        include_raw_github=False,     # telemt не публикует raw файлы
        include_statically=False,     # Statically тоже не работает с release-assets
    ),
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=1000,
    post_install=_post_install_telemt,
)


# ============================================================================
#  PackageSpec — telemt-panel (веб-панель)
# ============================================================================
TELEMT_PANEL_SPEC = PackageSpec(
    name="telemt-panel",
    filename_builder=lambda: f"telemt-panel-{detect_arch_libc()[0]}-linux-{detect_arch_libc()[1]}.tar.gz",
    mirror_urls_builder=lambda filename: build_mirror_urls(
        owner="amirotin",
        repo="telemt_panel",
        filename=filename,
        tag="latest",
        jsdelivr_hosts=(),
        include_raw_github=False,
        include_statically=False,
    ),
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=1000,
    post_install=_post_install_panel,
)
