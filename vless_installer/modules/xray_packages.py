"""
vless_installer/modules/xray_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для Xray-core артефактов:
  • XRAY_ZIP_SPEC — бинарный архив Xray-linux-{arch}.zip
  • XRAY_CHECKSUMS_SPEC — checksums.txt для SHA256 верификации
  • XRAY_INSTALLER_SPEC — install-release.sh bootstrap-скрипт

Используется xray_install.py для:
  • install_xray() — первичная установка (через zip + SHA256 verify)
  • _xray_do_upgrade() — обновление (через zip + SHA256 verify)
  • _xray_update_geo_runetfreedom() — обновление geo-файлов (уже мигрировано
    в geo_packages.py, здесь не повторяем)

До миграции xray_install.py содержал:
  • Inline 7-mirror список _ZIP_MIRRORS (прямой GitHub + 6 ghproxy)
  • Inline 3-mirror список _CHK_MIRRORS (прямой GitHub + 2 ghproxy)
  • ОДИН прямой URL в _xray_do_upgrade (БЕЗ зеркал вообще!)
  • Inline curl loop с --retry 2 + file magic check
  • Дублированный 7-mirror список в _xray_print_manual_download_hint

Особенности XRAY_ZIP_SPEC:
  • post_install делает:
      1. Fetch checksums.txt через отдельный fetch_package(XRAY_CHECKSUMS_SPEC)
         — это nested call, но необходимый для SHA256 верификации.
      2. Verify SHA256 zip vs checksums
      3. unzip → copy xray binary to /usr/local/bin/xray (chmod 0o755)
      4. Preserve runetfreedom .dat files (skip if existing >= threshold)
  • Возвращает False если SHA256 не совпал (MITM protection) — даёт
    fetch_package шанс попробовать следующее зеркало.

  • tag подставляется через filename_kwargs:
    fetch_package(XRAY_ZIP_SPEC, tag="v25.4.30", arch="64")

install_dests = [/usr/local/bin] — куда ставится бинарник xray.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from vless_installer.modules.xray_packages import (
        XRAY_ZIP_SPEC, XRAY_CHECKSUMS_SPEC, XRAY_INSTALLER_SPEC,
    )
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec, fetch_package
from vless_installer.modules.xray_mirrors import (
    get_xray_zip_mirrors,
    get_xray_checksums_mirrors,
    get_xray_installer_mirrors,
)


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# /usr/local/bin/xray — куда ставится бинарник.
_XRAY_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# /usr/local/share/xray — куда ставятся .dat файлы из zip.
_XRAY_SHARE_DIR = Path("/usr/local/share/xray")

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Минимальный размер Xray zip.
# Реальный размер: ~25 MB (xray binary + geo .dat файлы).
# 1 MB — нижний порог, отлавливает HTML-страницы 404 (раньше было >100_000).
_MIN_XRAY_ZIP_SIZE = 1_000_000

# Минимальный размер checksums.txt — маленький текстовый файл.
_MIN_CHECKSUMS_SIZE = 100

# Минимальный размер install-release.sh.
# Реальный размер: ~10-20 KB (bash скрипт).
_MIN_INSTALLER_SIZE = 1000

# Пороговые размеры geo-файлов для preservation логики.
_GEO_THRESHOLDS = {
    "geosite.dat": 10 * 1024 * 1024,  # 10 MB
    "geoip.dat":   15 * 1024 * 1024,  # 15 MB
}


# ============================================================================
#  mirror_urls_builder — обёртки для PackageSpec API
# ============================================================================
def _xray_zip_mirror_urls(filename: str, tag: str = "v25.4.30", arch: str = "64", **kw) -> list[str]:
    """Собирает URL для Xray zip через xray_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла конструируется из arch внутри
    get_xray_zip_mirrors().
    """
    return get_xray_zip_mirrors(tag=tag, arch=arch)


def _xray_checksums_mirror_urls(filename: str, tag: str = "v25.4.30", **kw) -> list[str]:
    """Собирает URL для checksums.txt через xray_mirrors."""
    return get_xray_checksums_mirrors(tag=tag)


def _xray_installer_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для install-release.sh через xray_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (install-release.sh).
    """
    return get_xray_installer_mirrors()


# ============================================================================
#  Вспомогательные: SHA256 верификация
# ============================================================================
def _verify_sha256_from_content(file_path: Path, checksums_content: str, file_name: str) -> bool:
    """Проверяет SHA256 файла file_path против содержимого checksums.txt.

    Возвращает True если hash совпал или если hash не найден в checksums
    (в этом случае верификация пропускается — как в старом _verify_sha256).
    Возвращает False если hash найден но НЕ совпал (MITM detection).
    """
    import re

    # Ищем строку вида: {sha256} *{filename}  или  {sha256} {filename}
    m = re.search(
        rf'^([0-9a-f]{{64}})\s+\*?{re.escape(file_name)}$',
        checksums_content,
        re.MULTILINE,
    )
    if not m:
        # Hash не найден — пропускаем верификацию (как в старом коде)
        return True

    expected = m.group(1)
    r = subprocess.run(
        ["sha256sum", str(file_path)],
        capture_output=True, text=True, check=False,
    )
    actual = r.stdout.split()[0] if r.stdout else ""
    return actual == expected


def _fetch_checksums_content(tag: str) -> str | None:
    """Скачивает checksums.txt через fetch_package(XRAY_CHECKSUMS_SPEC).

    Возвращает содержимое файла как строку, или None если скачать не удалось.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="xray_chk_"))
    try:
        # Используем dry_run=False, но spec ставит файл в /tmp через
        # install_dests. Проблема: fetch_package копирует в install_dests
        # с именем filename. Мы хотим прочитать содержимое, не ставить.
        # Решение: создаём временный spec с install_dests=[tmp_dir].
        chk_spec = PackageSpec(
            name="xray-checksums-tmp",
            filename_builder=lambda: "checksums.txt",
            mirror_urls_builder=_xray_checksums_mirror_urls,
            install_dests=[tmp_dir],
            manual_incoming_dir=Path("/nonexistent_manual_dir_for_chk_tmp"),
            min_size=_MIN_CHECKSUMS_SIZE,
        )
        ok = fetch_package(chk_spec, tag=tag, print_hint_on_failure=False)
        if not ok:
            return None
        chk_file = tmp_dir / "checksums.txt"
        if not chk_file.exists():
            return None
        return chk_file.read_text()
    except Exception:
        return None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
#  post_install — XRAY_ZIP_SPEC: SHA256 verify + unzip + preserve .dat
# ============================================================================
def _post_install_xray_zip(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает Xray zip, верифицирует SHA256, ставит бинарник.

    Шаги (повторяют логику из старого xray_install.py::install_xray):
      1. Проверка zip magic (file command или просто .zip extension)
      2. Fetch checksums.txt через _fetch_checksums_content(tag=...)
         — tag извлекается из URL зеркала или передаётся через closure.
         **Проблема**: post_install получает только (src, install_dests),
         без tag. Решение: используем _XRAY_CURRENT_TAG глобальную переменную,
         которая устанавливается перед вызовом fetch_package(XRAY_ZIP_SPEC).
      3. Verify SHA256 src vs checksums
      4. unzip → copy xray to /usr/local/bin/xray (chmod 0o755)
      5. Preserve runetfreedom .dat files (skip if existing >= threshold)

    Возвращает True при успехе. False если:
      • SHA256 не совпал (MITM detection) — даёт fetch_package шанс
        попробовать следующее зеркало.
      • unzip упал.
      • xray бинарник не найден в архиве.
    """
    # tag устанавливается вызывающим кодом через _XRAY_CURRENT_TAG
    # или через _xray_zip_context dict. Синхронизируем перед чтением.
    _sync_context()
    tag = _XRAY_CURRENT_TAG
    arch = _XRAY_CURRENT_ARCH
    zip_name = f"Xray-linux-{arch}.zip"

    # 1. SHA256 верификация
    if tag:
        chk_content = _fetch_checksums_content(tag)
        if chk_content is not None:
            if not _verify_sha256_from_content(src, chk_content, zip_name):
                # SHA256 не совпал — возможен MITM, отказываемся
                return False
            # SHA256 OK или hash не найден (пропуск) — продолжаем
        # Если checksums.txt не скачался — пропускаем верификацию
        # (как в старом _verify_sha256: "Не удалось загрузить checksums.txt
        # — верификация пропущена")

    # 2. Распаковка
    tmp_dir = Path(tempfile.mkdtemp(prefix="xray_extract_"))
    try:
        r = subprocess.run(
            ["unzip", "-o", str(src), "-d", str(tmp_dir)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 3. Поиск xray бинарника
        xray_bin_src = tmp_dir / "xray"
        if not xray_bin_src.exists():
            return False

        # 4. Установка бинарника
        if not install_dests:
            return False
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)
        xray_dest = dest_dir / "xray"
        shutil.copy2(str(xray_bin_src), str(xray_dest))
        xray_dest.chmod(0o755)

        # 5. Preserve runetfreedom .dat files
        _XRAY_SHARE_DIR.mkdir(parents=True, exist_ok=True)
        for dat in tmp_dir.glob("*.dat"):
            dest = _XRAY_SHARE_DIR / dat.name
            thr = _GEO_THRESHOLDS.get(dat.name, 0)
            if thr and dest.exists() and dest.stat().st_size >= thr:
                # Сохранён runetfreedom .dat — стандартный пропускаем
                pass
            else:
                shutil.copy2(str(dat), str(dest))

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# Глобальные переменные для передачи tag/arch в post_install.
# Устанавливаются вызывающим кодом перед fetch_package(XRAY_ZIP_SPEC).
# Это НЕ потокобезопасно, но xray_install.py работает в одном потоке
# (интерактивный инсталлятор), так что приемлемо.
_XRAY_CURRENT_TAG: str = ""
_XRAY_CURRENT_ARCH: str = "64"

# Альтернативный dict-based интерфейс для tag/arch контекста.
# Некоторые вызывающие сайты (в xray_install.py) используют _xray_zip_context
# dict вместо двух отдельных глобалов — поддерживаем оба для совместимости.
_xray_zip_context: dict = {"tag": "", "arch": "64"}


def _sync_context() -> None:
    """Синхронизирует _XRAY_CURRENT_TAG/ARCH из _xray_zip_context dict.

    Вызывается в начале _post_install_xray_zip чтобы подхватить значения,
    установленные через _xray_zip_context["tag"] = ... в вызывающем коде.
    """
    global _XRAY_CURRENT_TAG, _XRAY_CURRENT_ARCH
    if _xray_zip_context.get("tag"):
        _XRAY_CURRENT_TAG = _xray_zip_context["tag"]
    if _xray_zip_context.get("arch"):
        _XRAY_CURRENT_ARCH = _xray_zip_context["arch"]


# ============================================================================
#  post_install — XRAY_INSTALLER_SPEC: copy2 install-release.sh
# ============================================================================
def _post_install_xray_installer(src: Path, install_dests: list[Path]) -> bool:
    """Копирует install-release.sh в install_dests[0]/install-release.sh.

    Простой copy2 + chmod 0o755. Скрипт запускается вызывающим кодом через
    `bash install-release.sh install`.
    """
    if not install_dests:
        return False
    dest_dir = install_dests[0]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "install-release.sh"
    try:
        shutil.copy2(str(src), str(dest))
        dest.chmod(0o755)
        return True
    except Exception:
        return False


# ============================================================================
#  PackageSpec — Xray zip
# ============================================================================
XRAY_ZIP_SPEC = PackageSpec(
    name="Xray-core",                            # short name (для тестов и логов)
    filename_builder=lambda arch: f"Xray-linux-{arch}.zip",
    mirror_urls_builder=_xray_zip_mirror_urls,
    install_dests=_XRAY_INSTALL_DESTS,            # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,              # /root/
    min_size=_MIN_XRAY_ZIP_SIZE,                  # 1 MB
    post_install=_post_install_xray_zip,          # SHA256 + unzip + preserve .dat
)


# ============================================================================
#  PackageSpec — checksums.txt (для ручного скачивания, не для post_install)
# ============================================================================
# Этот spec используется только для скачивания checksums.txt в ручном режиме
# (через print_manual_hint). Внутри post_install XRAY_ZIP_SPEC используется
# _fetch_checksums_content с временным spec (см. выше).
XRAY_CHECKSUMS_SPEC = PackageSpec(
    name="Xray checksums.txt",
    filename_builder=lambda: "checksums.txt",
    mirror_urls_builder=_xray_checksums_mirror_urls,
    install_dests=[Path("/tmp")],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_CHECKSUMS_SIZE,
    # post_install=None — просто copy2 в /tmp/checksums.txt (default behavior)
)


# ============================================================================
#  PackageSpec — install-release.sh
# ============================================================================
XRAY_INSTALLER_SPEC = PackageSpec(
    name="Xray-installer",                        # short name (для тестов и логов)
    filename_builder=lambda: "install-release.sh",
    mirror_urls_builder=_xray_installer_mirror_urls,
    install_dests=[Path("/tmp")],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_INSTALLER_SIZE,
    post_install=_post_install_xray_installer,
)
