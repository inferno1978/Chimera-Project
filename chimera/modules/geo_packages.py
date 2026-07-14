"""
chimera/modules/geo_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec-инстансы для geosite.dat и geoip.dat — декларативное описание
пакетов для download_manager.fetch_package().

Этот модуль ОТДЕЛЁН от geo_mirrors.py (реестр URL-фабрик) и от geo_files.py
(оркестрация скачивания). Спеки пакетов — это связка «зеркала + пути
установки + post_install», которая говорит fetch_package() КАК качать и
КУДА ставить, не зная внутренних деталей.

АРХИТЕКТУРНАЯ ЗАЩИТА ОТ БАГА 21d7baf:
  PackageSpec.__post_init__ assert проверяет что manual_incoming_dir
  (/root/) НЕ совпадает ни с одним install_dest. Это физически запрещает
  создание spec'а с коллизией — баг «повторный вызов находит свой же файл
  в install_dests и не идёт в сеть» невозможен по конструкции.

Точки входа:
    from chimera.modules.geo_packages import GEOSITE_SPEC, GEOIP_SPEC
"""
from __future__ import annotations

import shutil
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.github_mirrors import build_mirror_urls
from chimera.modules.geo_mirrors import MIN_SIZES


# ============================================================================
#  КОНСТАНТЫ — пути установки (ТЕ ЖЕ что были в dest_dirs ранее)
# ============================================================================
# Xray ищет dat-файлы в трёх директориях — копируем во все три.
_CONFIG_DIR     = Path("/etc/xray")
_XRAY_SHARE_DIR = Path("/usr/local/share/xray")
_XRAY_ETC_DIR   = Path("/usr/local/etc/xray")

_GEO_INSTALL_DESTS: list[Path] = [_CONFIG_DIR, _XRAY_SHARE_DIR, _XRAY_ETC_DIR]

# manual_incoming_dir — ТОЛЬКО /root/. Не весь MANUAL_UPLOAD_PATHS.
# PackageSpec.__post_init__ assert гарантирует что /root/ не совпадает
# ни с одним install_dest — это структурная защита от бага 21d7baf.
_GEO_MANUAL_DIR = Path("/root")


# ============================================================================
#  post_install — копирование в 3 директории + chmod 644 + chown root:xray
# ============================================================================
def _post_install_geo(src: Path, install_dests: list[Path]) -> bool:
    """Копирует скачанный/ручной geo-файл во все install_dests.

    Делает то же что старый код в download_geo_files():
      • shutil.copy2(src → dest_dir/filename) для каждой dest_dir
      • dest.chmod(0o644)
      • chown root:xray (best-effort через core._run)

    Возвращает True при успехе. False только если ВСЕ копирования упали.
    """
    # Ленивый доступ к core._run для chown
    _run = None
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        _run = core._run
    except Exception:
        pass

    any_ok = False
    for dest_dir in install_dests:
        dest = dest_dir / src.name
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            dest.chmod(0o644)
            # chown root:xray — best-effort, как в старом коде
            if _run is not None:
                try:
                    _run(["chown", "root:xray", str(dest)], check=False, quiet=True)
                except Exception:
                    pass
            any_ok = True
        except Exception:
            pass

    return any_ok


# ============================================================================
#  PackageSpec — geosite.dat
# ============================================================================
GEOSITE_SPEC = PackageSpec(
    name="geosite.dat",
    filename_builder=lambda **kw: "geosite.dat",
    mirror_urls_builder=lambda filename: build_mirror_urls(
        owner="runetfreedom",
        repo="russia-v2ray-rules-dat",
        filename=filename,
        tag="latest",       # release GitHub / gh-proxy: releases/latest/download/
        ref="release",      # jsDelivr / raw GitHub / Statically: @release / /release/
    ),
    install_dests=_GEO_INSTALL_DESTS,     # [/etc/xray, /usr/local/share/xray, /usr/local/etc/xray]
    manual_incoming_dir=_GEO_MANUAL_DIR,   # /root/ — WinSCP-friendly
    min_size=MIN_SIZES["geosite.dat"],     # 3_000_000
    post_install=_post_install_geo,        # chmod 644 + chown root:xray
)


# ============================================================================
#  PackageSpec — geoip.dat
# ============================================================================
GEOIP_SPEC = PackageSpec(
    name="geoip.dat",
    filename_builder=lambda **kw: "geoip.dat",
    mirror_urls_builder=lambda filename: build_mirror_urls(
        owner="runetfreedom",
        repo="russia-v2ray-rules-dat",
        filename=filename,
        tag="latest",
        ref="release",
    ),
    install_dests=_GEO_INSTALL_DESTS,
    manual_incoming_dir=_GEO_MANUAL_DIR,
    min_size=MIN_SIZES["geoip.dat"],       # 10_000
    post_install=_post_install_geo,
)
