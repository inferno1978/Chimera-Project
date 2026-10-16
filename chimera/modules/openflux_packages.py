"""
chimera/modules/openflux_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec исходников OpenFlux для download_manager.fetch_package()
(конвенция mieru_packages.py / wdtt_packages.py / csqtt_packages.py).

ВСЕ сетевые загрузки модуля openflux идут через download_manager:
  1. Go-тулчейн — ОБЩИЙ GO_TOOLCHAIN_SPEC из go_toolchain_packages.py
     (как wdtt / webdav_tunnel / olcrtc; зеркала go.dev → golang.google.cn
     → aliyun → tencent, /root-фолбэк, post_install с симлинками в
     /usr/local/bin). Дублировать спек здесь НЕ нужно — конвенция
     проекта: один Go-спек на все source-build модули.
  2. OPENFLUX_SRC_SPEC (этот файл) — исходники OpenFlux тарболлом по
     sha-пину: codeload.github.com → 3 gh-proxy обёртки.

Что это даёт по сравнению с прошлым подходом (голый urllib + git clone):
  • зеркальный fallback + WinSCP-friendly manual incoming (/root/<file>)
  • min_size-защита от усечённых загрузок и HTML-заглушек
  • единый прогресс-вывод и диагностика провала (print_manual_hint)
  • git больше НЕ нужен для установки (tarball распаковывается tar'ом);
    ls-remote остаётся только для разрешения sha свежего main (best-effort)

Инвариант PackageSpec: manual_incoming_dir (/root/) != install_dests
(/tmp/openflux_dl) — баг 21d7baf невозможен по конструкции.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from chimera.modules.download_manager import PackageSpec


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

_INSTALL_TMP = Path("/tmp/openflux_dl")   # install_dests: post_install ставит сам
_MANUAL_DIR = Path("/root")               # manual incoming (WinSCP-friendly)

_OWNER_REPO = "p1neappleXpress/OpenFlux"
_GH_ARCHIVE = f"https://github.com/{_OWNER_REPO}/archive"
_CODELOAD   = f"https://codeload.github.com/{_OWNER_REPO}/tar.gz"

# gh-proxy префиксы — конвенция проекта (awg_transport_mirrors и др.)
_GH_PROXY_PREFIXES = (
    "https://gh-proxy.com/",
    "https://ghproxy.net/",
    "https://gh.llkk.cc/",
)


# ============================================================================
#  Хелперы URL
# ============================================================================

def _ref_slug(ref: str) -> str:
    """Реф → безопасный кусок имени файла.

    '461905369bd8...' → как есть; 'refs/heads/main' → 'refs-heads-main'
    (слэши в имени файла /root/<name> недопустимы)."""
    out = "".join(ch if (ch.isalnum() or ch in "._-") else "-"
                  for ch in (ref or "x"))
    return out[:40] or "x"


def _src_mirror_urls(filename: str, ref: str = "", **kw) -> list[str]:
    """Тарбол исходников по ref (40-символьный sha или refs/heads/main).

    Прямой codeload + 3 gh-proxy обёртки github-archive. Запрос по
    точному sha иммутабелен — кеш зеркала не может подсунуть «не ту»
    версию; refs/heads/main на кеше может отставать (модуль предупреждает)."""
    r = ref or _ref_slug(filename)
    urls = [f"{_CODELOAD}/{r}"]
    for pref in _GH_PROXY_PREFIXES:
        urls.append(f"{pref}{_GH_ARCHIVE}/{r}.tar.gz")
    return urls


# ============================================================================
#  post_install callback
# ============================================================================

def _post_install_src_tarball(src: Path, dests: list) -> bool:
    """Распаковка исходников в /opt/openflux/src (strip top-level dir).

    Верификация содержимого: go.mod + main.go обязаны быть (защита от
    HTML-заглушек зеркал, отдавших 200 с ошибкой)."""
    if not shutil.which("tar"):
        print("  ✗ tar не найден — нечем распаковывать исходники")
        return False
    target = Path("/opt/openflux/src")
    subprocess.run(["rm", "-rf", str(target)], check=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["tar", "--strip-components=1", "-C", str(target), "-xzf", str(src)],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  ✗ tar: {(r.stderr or '')[-200:]}")
        return False
    for probe in ("go.mod", "main.go"):
        if not (target / probe).exists():
            print(f"  ✗ в tarball нет {probe} — это не исходники OpenFlux")
            subprocess.run(["rm", "-rf", str(target)], check=False)
            return False
    return True


# ============================================================================
#  PackageSpec
# ============================================================================

# Исходники OpenFlux. min_size 30 КБ: репо ~5.3k LOC + go.sum; тарбол
# ~100-300 КБ, но меньше 30 КБ — точно мусор/заглушка.
OPENFLUX_SRC_SPEC = PackageSpec(
    name="OpenFlux sources",
    filename_builder=lambda ref="", **kw:
        f"openflux-{_ref_slug(ref)}.tar.gz",
    mirror_urls_builder=_src_mirror_urls,
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=30_000,
    post_install=_post_install_src_tarball,
)
