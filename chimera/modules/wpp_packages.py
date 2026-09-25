#!/usr/bin/env python3
"""
chimera/modules/wpp_packages.py
────────────────────────────────────────────────────────────────────────────────
PackageSpec для скачивания тарбола фронтенда WPP через download_manager.

Архитектура:
  • Источник:     тег v{version} репозитория POLESNIESOVETI12/web-panel-proxy
  • Mirror ladder: wpp_mirrors.front_mirror_urls (8 URL: codeload + 6 gh-proxy
                   wrapperов + прямой GitHub archive)
  • manual_incoming_dir = /root  (WinSCP-friendly: пользователь может положить
                   тарбол вручную если все зеркала недоступны)
  • install_dests = [/var/lib/xray-installer]  (после post_install распакованный
                   фронт попадает в /var/lib/xray-installer/wpp_panel_www/)
  • min_size = 200_000 байт  (тарбол v2.4.2 ~ 500 KB — меньше 200 KB точно
                   подозрительно: html-redirect от CDN вместо tarball)

post_install callback:
  1. Проверка magic bytes gzip (1f 8b) — отклоняет HTML-страницы ошибок CDN.
  2. Распаковка tar.gz в staging dir.
  3. Поиск subdir "web-panel-proxy-<tag>/" внутри тарбола.
  4. Копирование содержимого (не весь subdir, а только "panel/public/") в
     staging, затем atomic swap (os.replace) в www.
  5. Возвращает True при успехе, False — fetch_package попробует след. зеркало.

NB: post_install НЕ перезаписывает живой /var/lib/xray-installer/wpp_panel_www/
    напрямую. Сначала пишет в staging, потом wpp_panel._update_front() делает
    atomic swap (через rename). Если staging уже на месте — _update_front
    перемещает. Это гарантирует, что упавший mid-write post_install не
    оставит www в сломанном состоянии.
"""
from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path
from typing import Optional

# Bootstrap корня проекта (для прямого запуска)
if __package__ in (None, ""):
    import sys
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from chimera.modules.download_manager import PackageSpec  # noqa: E402
from chimera.modules.wpp_mirrors import front_mirror_urls, UPSTREAM_REPO_FULL  # noqa: E402

# ─── КОНСТАНТЫ ────────────────────────────────────────────────────────────────

STATE_DIR    = Path("/var/lib/xray-installer")
WWW_DIR       = STATE_DIR / "wpp_panel_www"     # vendored frontend
STAGING_DIR  = STATE_DIR / "wpp_panel_staging"  # atomic-swap staging

# Версия порта (фронт+контракт синхронизированы — см. changelog).
# bump при изменениях API-контракта между wpp_panel.py и wpp_panel_web.py.
WPP_FRONT_VERSION = "2.4.2"

# Минимальный размер тарбола (v2.4.2 ~ 500 KB; с локализацией ~ 1 MB).
# Меньше 200 KB — почти наверняка HTML-редирект CDN или 404 страница.
WPP_TARBALL_MIN_SIZE = 200_000

# Subpath внутри тарбола: <repo>-<tag>/panel/public/ — нет, у WPP файлы
# лежат в корне репо, поэтому просто <repo>-<tag>/. Берём корень целиком.
# (WPP устроен проще Triple Panel — нет подкаталога panel/public).
_TARBALL_TOP_SUBDIR_PREFIX = f"{UPSTREAM_REPO_FULL.split('/')[-1]}-"


# ─── POST_INSTALL CALLBACK ────────────────────────────────────────────────────

def _post_install_front(src: Path, install_dests: list[Path]) -> bool:
    """
    Callback для fetch_package: распаковывает тарбол фронтенда в STAGING_DIR.

    Workflow:
      1. magic bytes: gzip (1f 8b) — иначе отклонить (HTML-редирект CDN).
      2. tar.open(mode='r:gz') + проверка на path traversal (безопасные имена).
      3. Распаковка во временный subdir внутри STAGING_DIR.
      4. Перенос содержимого из subdir-<tag>/ в STAGING_DIR (без subdir).
      5. Удаление subdir.

    Возвращает True при успехе, False — fetch_package попробует следующее
    зеркало (паттерн hysteria2_packages._post_install_hysteria2 — runtime
    verify-then-replace).

    Финальный atomic swap staging → www делает _update_front() в wpp_panel.py
    (после успешного smoke-теста — иначе rollback).
    """
    try:
        # 1. magic bytes gzip
        with src.open("rb") as f:
            head = f.read(2)
        if head != b"\x1f\x8b":
            print(f"[WPP-FRONT] not a gzip: first bytes = {head!r}, expected 1f8b",
                  flush=True)
            return False

        # 2. Подготовка staging
        if STAGING_DIR.exists():
            shutil.rmtree(STAGING_DIR, ignore_errors=True)
        STAGING_DIR.mkdir(parents=True, exist_ok=True)

        # 3. Распаковка с защитой от path traversal (pathlib.Path от
        # tarball-имен может содержать ../). Используем тот же паттерн что
        # triple_panel._extract_front: extractall безопасен если tarfile
        # настроен на фильтрацию (Python 3.12+ — data filter).
        try:
            # Python 3.12+: use 'data' filter (заменяет устаревший manual check)
            with tarfile.open(src, mode="r:gz") as tar:
                try:
                    tar.extractall(STAGING_DIR, filter="data")
                except TypeError:
                    # Python 3.11 — filter= не поддерживается, fallback на
                    # ручную проверку имен (как в triple_panel._extract_front).
                    for member in tar.getmembers():
                        target = (STAGING_DIR / member.name).resolve()
                        if not str(target).startswith(str(STAGING_DIR.resolve())):
                            print(f"[WPP-FRONT] path traversal attempt: {member.name}",
                                  flush=True)
                            return False
                    tar.extractall(STAGING_DIR)
        except tarfile.TarError as exc:
            print(f"[WPP-FRONT] tar error: {type(exc).__name__}: {exc}",
                  flush=True)
            return False

        # 4. Найдём subdir <repo>-<tag>/ (codeload и github.com archive оба
        # кладут файлы в такой subdir)
        subdirs = [d for d in STAGING_DIR.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and subdirs[0].name.startswith(_TARBALL_TOP_SUBDIR_PREFIX):
            top = subdirs[0]
        else:
            # Нет subdir или их несколько — берём содержимое STAGING_DIR как есть.
            # (для не-codeload зеркал, которые могут не добавлять subdir)
            top = STAGING_DIR

        # 5. Переносим содержимое top/ в STAGING_DIR (flatten)
        if top is not STAGING_DIR:
            for item in top.iterdir():
                target = STAGING_DIR / item.name
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target, ignore_errors=True)
                    else:
                        target.unlink(missing_ok=True)
                shutil.move(str(item), str(target))
            # удаляем пустой subdir
            try:
                top.rmdir()
            except OSError:
                pass

        # 6. Проверяем что распаковали что-то осмысленное — есть хотя бы один
        # .py файл (panel source) или README.md
        has_python = any(STAGING_DIR.glob("*.py"))
        has_readme = (STAGING_DIR / "README.md").exists()
        if not (has_python or has_readme):
            print(f"[WPP-FRONT] staging empty/no-python/no-readme — rejected",
                  flush=True)
            shutil.rmtree(STAGING_DIR, ignore_errors=True)
            return False

        return True

    except Exception as exc:  # noqa: BLE001
        print(f"[WPP-FRONT] post_install failed: {type(exc).__name__}: {exc}",
              flush=True)
        # Cleanup staging чтобы не оставить мусор
        try:
            shutil.rmtree(STAGING_DIR, ignore_errors=True)
        except Exception:
            pass
        return False


# ─── PACKAGE SPEC ─────────────────────────────────────────────────────────────

def _filename_builder(version: str = "", **_kwargs) -> str:
    """filename_builder для PackageSpec — формирует имя файла тарбола."""
    ver = (version or WPP_FRONT_VERSION).lstrip("v")
    return f"web-panel-proxy-v{ver}.tar.gz"


# Главный PackageSpec — фронтенд WPP.
# manual_incoming_dir=/root — НЕ равен install_dests (assert в __post_init__).
# install_dests=[STATE_DIR] — post_install распаковывает в STAGING_DIR (внутри
# STATE_DIR), а не в install_dests напрямую (это нормально — install_dests
# служит только как маркер "куда ассоциирован пакет"; реально пишет post_install).
WPP_FRONT_SPEC = PackageSpec(
    name=f"WPP front v{WPP_FRONT_VERSION}",
    filename_builder=_filename_builder,
    mirror_urls_builder=front_mirror_urls,
    install_dests=[STATE_DIR],
    manual_incoming_dir=Path("/root"),
    min_size=WPP_TARBALL_MIN_SIZE,
    post_install=_post_install_front,
)


# ─── Список файлов для резервного копирования (для backup_registry) ──────────
# NB: НЕ определена get_backup_paths() на уровне модуля, потому что модуль
# wpp_packages.py — это spec для скачивания, не инсталлятор. get_backup_paths()
# определяется в wpp_panel.py после install (как у triple_panel.py).


if __name__ == "__main__":
    # Smoke-проверка
    import json
    spec = WPP_FRONT_SPEC
    info = {
        "name": spec.name,
        "filename": spec.filename_builder(version="2.4.2"),
        "install_dests": [str(d) for d in spec.install_dests],
        "manual_incoming_dir": str(spec.manual_incoming_dir),
        "min_size": spec.min_size,
        "first_mirror": spec.mirror_urls_builder(
            filename=spec.filename_builder(version="2.4.2"),
            version="2.4.2",
        )[0],
        "total_mirrors": len(spec.mirror_urls_builder(
            filename=spec.filename_builder(version="2.4.2"),
            version="2.4.2",
        )),
        "has_post_install": spec.post_install is not None,
    }
    print(json.dumps(info, indent=2, ensure_ascii=False))
