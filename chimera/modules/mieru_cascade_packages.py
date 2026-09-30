"""
chimera/modules/mieru_cascade_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для download manager — зависимость mieru_cascade (redsocks).

redsocks не публикуется на GitHub как .deb — официальный путь установки
в дистрибутиве это пакет из пула (universe). Схема зеркал:

  • Ubuntu 24.04 (noble, подтверждено на прод-серверах проекта 01.10):
    redsocks_0.5-2build4_amd64.deb, 56088 байт
    (apt-get --print-uris: archive.ubuntu.com / mirror.yandex.ru)
  • Ubuntu 22.04 (jammy): redsocks_0.5-1build1_amd64.deb
  • Debian 12: redsocks_0.5-1+b1_amd64.deb (запасные кандидаты)

Кандидаты перебираются по очереди (fetch_package на каждый spec);
post_install = dpkg -i — внутренние md5sums .deb дают проверку целостности
лучше внешнего .sha256sum, которого в пуле дистрибутива не существует.

Fallback за пределами модуля (mieru_cascade._install_redsocks):
apt-get install -y redsocks с честным warn.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from chimera.modules.download_manager import PackageSpec

# Хосты пула: yandex-зеркало первым (RU-friendly для Entry в РФ),
# archive.ubuntu.com вторым; security дублирует archive
_UBUNTU_HOSTS = [
    "http://mirror.yandex.ru/ubuntu",
    "http://archive.ubuntu.com/ubuntu",
]
_DEBIAN_HOSTS = [
    "http://mirror.yandex.ru/debian",
    "http://ftp.debian.org/debian",
]
_POOL_PATH = "pool/universe/r/redsocks"   # у Debian: pool/main/r/redsocks

# Порядок = приоритет; фильтруется по /etc/os-release в redsocks_candidates
_ALL_CANDIDATES = [
    # ubuntu 24.04 (noble) — подтверждён на прод-серверах 01.10.2026
    ("ubuntu", "24.04", "redsocks_0.5-2build4_amd64.deb",
     ["pool/universe/r/redsocks"], _UBUNTU_HOSTS),
    # ubuntu 22.04 (jammy)
    ("ubuntu", "22.04", "redsocks_0.5-1build1_amd64.deb",
     ["pool/universe/r/redsocks"], _UBUNTU_HOSTS),
    # debian 12 (bookworm) / 11 (bullseye) — совпадающий билд
    ("debian", "*", "redsocks_0.5-1+b1_amd64.deb",
     ["pool/main/r/redsocks"], _DEBIAN_HOSTS),
    ("debian", "*", "redsocks_0.5-1_amd64.deb",
     ["pool/main/r/redsocks"], _DEBIAN_HOSTS),
]

_MIN_SIZE = 50_000          # фактический размер noble-пакета 56088
_INSTALL_DEST = Path("/tmp/mieru_cascade_packages")


def _os_release() -> tuple:
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            data = {}
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')
        return data.get("ID", "").lower(), data.get("VERSION_ID", "")
    except OSError:
        return "", ""


def redsocks_candidates() -> list:
    """Имена .deb-файлов в порядке приоритета для текущего дистрибутива."""
    distro_id, ver = _os_release()
    out = []
    for d, v, fn, _paths, _hosts in _ALL_CANDIDATES:
        if d != distro_id:
            continue
        if v != "*" and not ver.startswith(v):
            continue
        out.append(fn)
    if not out:
        # неизвестный дистрибутив — перебираем всё (первым noble)
        out = [c[2] for c in _ALL_CANDIDATES]
    return out


def _post_install_deb(tmp_path: Path, dests: list) -> bool:
    r = subprocess.run(["dpkg", "-i", str(tmp_path)],
                       capture_output=True, text=True, check=False, timeout=60)
    return r.returncode == 0


def redsocks_spec_for(filename: str) -> PackageSpec:
    """PackageSpec для одного .deb-кандидата redsocks.

    Фикс бага деплоя 01.10 (live B): download_manager вызывает
    mirror_urls_builder(filename=..., **kwargs) — лямбда обязана
    принимать kwarg 'filename' (иначе TypeError).
    """
    urls = []
    for _d, _v, fn, paths, hosts in _ALL_CANDIDATES:
        if fn != filename:
            continue
        for h in hosts:
            for p in paths:
                urls.append(f"{h}/{p}/{fn}")
    if not urls:      # неизвестный файл — хотя бы yandex/ubuntu
        for h in _UBUNTU_HOSTS:
            urls.append(f"{h}/{_POOL_PATH}/{filename}")
    _fixed_urls = tuple(urls)

    def _urls(filename: str = "", **kw) -> list:
        return list(_fixed_urls)

    return PackageSpec(
        name=f"redsocks ({filename})",
        filename_builder=lambda fn=filename: fn,
        mirror_urls_builder=_urls,
        install_dests=[_INSTALL_DEST],
        manual_incoming_dir=Path("/root"),
        min_size=_MIN_SIZE,
        post_install=_post_install_deb,
    )
