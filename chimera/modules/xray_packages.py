"""
chimera/modules/xray_packages.py
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
    from chimera.modules.xray_packages import (
        XRAY_ZIP_SPEC, XRAY_CHECKSUMS_SPEC, XRAY_INSTALLER_SPEC,
    )
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.modules.download_manager import PackageSpec, fetch_package
from chimera.modules.xray_mirrors import (
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

# Минимальный размер .dgst файла (XTLS/Xray-core формат).
# Реальный размер: ~299 bytes (MD5 + SHA1 + SHA256 + SHA512 строки).
# 100 — нижний порог, отлавливает HTML-страницы 404.
_MIN_DGST_SIZE = 100

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


def _xray_checksums_mirror_urls(filename: str, tag: str = "v25.4.30", arch: str = "64", **kw) -> list[str]:
    """Собирает URL для .dgst файла через xray_mirrors.

    XTLS/Xray-core НЕ публикует единый checksums.txt. Вместо этого рядом
    с каждым .zip ассетом лежит .dgst файл (например Xray-linux-64.zip.dgst)
    с MD5/SHA1/SHA256/SHA512 хешами. Использование checksums.txt приводило
    к 404 на всех зеркалах и SHA256 верификация всегда пропускалась.
    """
    return get_xray_checksums_mirrors(tag=tag, arch=arch)


def _xray_installer_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для install-release.sh через xray_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (install-release.sh).
    """
    return get_xray_installer_mirrors()


# ============================================================================
#  Вспомогательные: SHA256 верификация
# ============================================================================
def _verify_sha256_from_dgst(file_path: Path, dgst_content: str) -> bool:
    """Проверяет SHA256 файла file_path против содержимого .dgst файла.

    XTLS/Xray-core публикует .dgst файлы в формате:
        MD5= 7b4ea9f0e3590ab6b4a239c9531b1043
        SHA1= ed009f0648de0628c20f09dfc726a54607f07918
        SHA2-256= aa11c3685c71da0ffc71e511db50404609e7e963bb914b048f59a6a00af8930e
        SHA2-512= 7dbde63e7e56a86fc3d52c04647c3a9050bf848d55ba55c4b996a286e33fefc8...

    Возвращает True если hash совпал или если SHA256 строка не найдена
    (в этом случае верификация пропускается).
    Возвращает False если SHA256 найден но НЕ совпал (MITM detection).
    """
    import re

    # Ищем строку вида: SHA2-256= <64 hex chars>
    m = re.search(r'^SHA2-256=\s*([0-9a-f]{64})\s*$', dgst_content, re.MULTILINE)
    if not m:
        # Hash не найден — пропускаем верификацию
        return True

    expected = m.group(1)
    r = subprocess.run(
        ["sha256sum", str(file_path)],
        capture_output=True, text=True, check=False,
    )
    actual = r.stdout.split()[0] if r.stdout else ""
    return actual == expected


def _fetch_dgst_content(tag: str, arch: str = "64") -> str | None:
    """Скачивает Xray-linux-{arch}.zip.dgst через fetch_package.

    XTLS/Xray-core НЕ публикует единый checksums.txt — вместо него рядом с
    каждым .zip ассетом лежит .dgst файл с MD5/SHA1/SHA256/SHA512 хешами.
    Старый _fetch_checksums_content() искал несуществующий checksums.txt и
    всегда возвращал None → SHA256 верификация всегда skip'алась.

    Возвращает содержимое .dgst файла как строку, или None если скачать не удалось.
    """
    dgst_filename = f"Xray-linux-{arch}.zip.dgst"
    tmp_dir = Path(tempfile.mkdtemp(prefix="xray_dgst_"))
    try:
        # spec ставит файл в tmp_dir с именем dgst_filename.
        chk_spec = PackageSpec(
            name="xray-dgst-tmp",
            # **kw обязателен — fetch_package(chk_spec, tag=tag, arch=arch, ...)
            # передаёт всё в filename_kwargs. Без **kw будет TypeError.
            filename_builder=lambda arch="64", **kw: dgst_filename,
            mirror_urls_builder=_xray_checksums_mirror_urls,
            install_dests=[tmp_dir],
            manual_incoming_dir=Path("/nonexistent_manual_dir_for_dgst_tmp"),
            min_size=_MIN_DGST_SIZE,
        )
        ok = fetch_package(chk_spec, tag=tag, arch=arch, print_hint_on_failure=False)
        if not ok:
            return None
        # fetch_package сохраняет файл в tmp_dir с именем
        # "_download_mgr_{filename}" (см. download_manager.py:182), а не {filename}.
        # Проверяем оба варианта — на случай если реализация изменится.
        dgst_file = tmp_dir / dgst_filename
        if not dgst_file.exists():
            dgst_file = tmp_dir / f"_download_mgr_{dgst_filename}"
        if not dgst_file.exists():
            return None
        return dgst_file.read_text()
    except (TypeError, AttributeError, ValueError) as e:
        # ВНУТРЕННЯЯ ОШИБКА — баг в spec'е или логике (не сеть).
        # Логируем в stderr чтобы не маскировать регрессии под "сеть недоступна".
        import sys
        print(f"[xray_packages._fetch_dgst_content] ВНУТРЕННЯЯ ОШИБКА: {type(e).__name__}: {e}",
              file=sys.stderr)
        return None
    except Exception:
        # Сетевые ошибки (URLError, TimeoutError, OSError и т.д.) — штатный
        # случай "сеть недоступна", возвращаем None без шума.
        return None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
#  post_install — XRAY_ZIP_SPEC: SHA256 verify + unzip + preserve .dat
# ============================================================================
def _post_install_xray_zip(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает Xray zip, верифицирует SHA256, ставит бинарник.

    Шаги:
      1. Fetch Xray-linux-{arch}.zip.dgst через _fetch_dgst_content(tag, arch)
      2. Verify SHA256 src vs .dgst
      3. unzip → copy xray to /usr/local/bin/xray (chmod 0o755)
      4. Preserve runetfreedom .dat files (skip if existing >= threshold)

    Возвращает True при успехе. False если:
      • SHA256 не совпал (MITM detection) — даёт fetch_package шанс
        попробовать следующее зеркало.
      • unzip упал.
      • xray бинарник не найден в архиве.
      • Ошибка copy2/chmod/mkdir — диагностика печатается в stderr.
    """
    import sys

    # tag устанавливается вызывающим кодом через _XRAY_CURRENT_TAG
    # или через _xray_zip_context dict. Синхронизируем перед чтением.
    _sync_context()
    tag = _XRAY_CURRENT_TAG
    arch = _XRAY_CURRENT_ARCH

    # 1. SHA256 верификация через .dgst файл
    global _XRAY_SHA256_STATUS
    _XRAY_SHA256_STATUS = ""  # сброс перед новой попыткой
    if not tag:
        _XRAY_SHA256_STATUS = "no_tag"
    else:
        dgst_content = _fetch_dgst_content(tag, arch)
        if dgst_content is None:
            _XRAY_SHA256_STATUS = "skipped"
        else:
            if not _verify_sha256_from_dgst(src, dgst_content):
                # SHA256 не совпал — возможен MITM, отказываемся
                _XRAY_SHA256_STATUS = "failed"
                print(f"[xray_post_install] SHA256 mismatch — possible MITM, refusing zip", file=sys.stderr)
                return False
            _XRAY_SHA256_STATUS = "verified"
        # Если _XRAY_SHA256_STATUS == "skipped" — продолжаем (как в старом
        # _verify_sha256: "Не удалось загрузить .dgst — верификация пропущена").

    # 2. Распаковка
    tmp_dir = Path(tempfile.mkdtemp(prefix="xray_extract_"))
    try:
        r = subprocess.run(
            ["unzip", "-o", str(src), "-d", str(tmp_dir)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[xray_post_install] unzip failed (rc={r.returncode}): {r.stderr[:300]}", file=sys.stderr)
            return False

        # 3. Поиск xray бинарника
        xray_bin_src = tmp_dir / "xray"
        if not xray_bin_src.exists():
            print(f"[xray_post_install] xray binary not found in zip", file=sys.stderr)
            print(f"                archive contents: {sorted(p.name for p in tmp_dir.iterdir())}", file=sys.stderr)
            return False

        # 4. Установка бинарника
        if not install_dests:
            print(f"[xray_post_install] install_dests is empty", file=sys.stderr)
            return False
        dest_dir = install_dests[0]
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[xray_post_install] mkdir {dest_dir} failed: {type(e).__name__}: {e}", file=sys.stderr)
            return False
        xray_dest = dest_dir / "xray"
        try:
            # Если xray service запущен — copy2 может упасть на TRUNCATE.
            # unlink + copy2 работает надёжнее.
            if xray_dest.exists():
                try:
                    xray_dest.unlink()
                except Exception:
                    pass
            shutil.copy2(str(xray_bin_src), str(xray_dest))
            xray_dest.chmod(0o755)
        except Exception as e:
            print(f"[xray_post_install] copy2/chmod {xray_dest} failed: {type(e).__name__}: {e}", file=sys.stderr)
            return False

        # 5. Preserve runetfreedom .dat files
        try:
            _XRAY_SHARE_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[xray_post_install] mkdir {_XRAY_SHARE_DIR} failed: {type(e).__name__}: {e}", file=sys.stderr)
            return False
        for dat in tmp_dir.glob("*.dat"):
            dest = _XRAY_SHARE_DIR / dat.name
            thr = _GEO_THRESHOLDS.get(dat.name, 0)
            if thr and dest.exists() and dest.stat().st_size >= thr:
                # Сохранён runetfreedom .dat — стандартный пропускаем
                pass
            else:
                try:
                    shutil.copy2(str(dat), str(dest))
                except Exception as e:
                    print(f"[xray_post_install] copy2 {dat.name} failed: {type(e).__name__}: {e}", file=sys.stderr)
                    return False

        return True

    except Exception as e:
        # Catch-all с диагностикой — больше НЕ глотаем молча.
        print(f"[xray_post_install] unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# Глобальные переменные для передачи tag/arch в post_install.
# Устанавливаются вызывающим кодом перед fetch_package(XRAY_ZIP_SPEC).
# Это НЕ потокобезопасно, но xray_install.py работает в одном потоке
# (интерактивный инсталлятор), так что приемлемо.
_XRAY_CURRENT_TAG: str = ""
_XRAY_CURRENT_ARCH: str = "64"

# Результат последней SHA256 верификации. Устанавливается post_install'ом,
# читается вызывающим кодом чтобы НЕ печатать ложное "SHA256 ОК" когда
# верификация была пропущена (checksums.txt недоступен).
# Значения: "verified" (SHA256 совпал), "skipped" (checksums недоступен),
# "no_tag" (tag не передан), "" (post_install не вызывался).
_XRAY_SHA256_STATUS: str = ""

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
    # ВАЖНО: filename_builder обязан принимать ВСЕ kwargs из **filename_kwargs.
    # Call site в xray_install.py передаёт tag=latest_tag, arch=xray_arch.
    # filename строится только из arch, но tag тоже принимается (через **kw),
    # иначе TypeError при вызове spec.filename_builder(tag=..., arch=...).
    filename_builder=lambda arch, **kw: f"Xray-linux-{arch}.zip",
    mirror_urls_builder=_xray_zip_mirror_urls,
    install_dests=_XRAY_INSTALL_DESTS,            # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,              # /root/
    min_size=_MIN_XRAY_ZIP_SIZE,                  # 1 MB
    post_install=_post_install_xray_zip,          # SHA256 + unzip + preserve .dat
)


# ============================================================================
#  PackageSpec — .dgst файл (для ручного скачивания, не для post_install)
# ============================================================================
# Этот spec используется только для скачивания .dgst файла в ручном режиме
# (через print_manual_hint). Внутри post_install XRAY_ZIP_SPEC используется
# _fetch_dgst_content с временным spec (см. выше).
# XTLS/Xray-core НЕ публикует checksums.txt — только .dgst рядом с каждым .zip.
XRAY_CHECKSUMS_SPEC = PackageSpec(
    name="Xray .dgst",
    # filename строится из arch: Xray-linux-{arch}.zip.dgst
    filename_builder=lambda arch="64", **kw: f"Xray-linux-{arch}.zip.dgst",
    mirror_urls_builder=_xray_checksums_mirror_urls,
    install_dests=[Path("/tmp")],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_DGST_SIZE,
    # post_install=None — просто copy2 в /tmp/Xray-linux-{arch}.zip.dgst
)


# ============================================================================
#  PackageSpec — install-release.sh
# ============================================================================
XRAY_INSTALLER_SPEC = PackageSpec(
    name="Xray-installer",                        # short name (для тестов и логов)
    filename_builder=lambda **kw: "install-release.sh",
    mirror_urls_builder=_xray_installer_mirror_urls,
    install_dests=[Path("/tmp")],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_INSTALLER_SIZE,
    post_install=_post_install_xray_installer,
)
