"""
vless_installer/modules/webdav_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для исходников webdav-tunnel (spkprsnts/webdav-tunnel).

Используется webdav_tunnel.py для скачивания source-tarball'а и сборки
webdav-tunnel бинарника. До миграции webdav_tunnel.py делал это ad-hoc через
urllib.request.urlretrieve + tar + go build + copy2.

Особенности post_install (отличия от wdtt_packages.py):
  • Build target: `.` (весь пакет) вместо `./server.go` (wdtt).
    webdav-tunnel — единый бинарник для всех -mode, как описано в README.
  • go mod tidy: выполняется ТОЛЬКО как fallback после неудачной первой
    попытки go build (в wdtt — до первой попытки).
  • Atomic-replace: ОТСУТСТВУЕТ (в wdtt — есть).
    webdav_tunnel.py просто делает shutil.copy2(built, _BIN_PATH), что может
    вызвать [Errno 26] Text file busy на работающем сервисе. Это известное
    ограничение старого кода — НЕ исправляем без явного решения пользователя
    (поведение должно сохраниться 1-в-1 после миграции).

    TODO: можно переиспользовать _atomic_replace_binary из wdtt_packages.py
    если пользователь одобрит исправление. Сейчас оставлено как есть.

install_dests = [/tmp/webdav_packages] — временная директория, post_install
игнорирует её и ставит бинарник в /usr/local/bin/webdav-tunnel.

Точки входа:
    from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.webdav_mirrors import get_webdav_source_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# install_dests — временная директория (post_install игнорирует её).
_INSTALL_TMP = Path("/tmp/webdav_packages")

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Целевой путь для собранного бинарника.
_WEBDAV_BIN_PATH = Path("/usr/local/bin/webdav-tunnel")

# Минимальный размер source-tarball'а.
# Реальный размер: ~50-200 KB. 1 KB — нижний порог от 404 HTML.
_MIN_SOURCE_TARBALL_SIZE = 1000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _webdav_source_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для исходников webdav-tunnel через webdav_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (webdav-tunnel-main.tar.gz).
    """
    return get_webdav_source_mirrors()


# ============================================================================
#  post_install — распаковка + go build + copy2 (без atomic-replace)
# ============================================================================
def _post_install_webdav_source(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает source-tarball, собирает webdav-tunnel, копирует в
    /usr/local/bin/webdav-tunnel.

    Полная репликация логики из старого webdav_tunnel.py._build_webdav_tunnel:
      1. tar -xzf во временную директорию
      2. Поиск webdav-tunnel-* директории
      3. go build -o webdav-tunnel -ldflags "-s -w" .
         env: CGO_ENABLED=0, GOOS=linux, GOARCH=amd64 (hardcoded, как в wdtt)
      4. Если build упал — go mod tidy (GOSUMDB=off) + повторный build
      5. copy2 в /usr/local/bin/webdav-tunnel + chmod 0o755
         (БЕЗ atomic-replace — см. комментарий в module docstring)

    Go toolchain должен быть установлен ДО этого вызова — вызывающий код
    отвечает за _ensure_go().

    Возвращает True при успехе, False при любой ошибке.
    """
    import os

    tmp = Path(tempfile.mkdtemp())
    try:
        # 1. Распаковка
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск директории с исходниками
        src_dirs = list(tmp.glob("webdav-tunnel-*"))
        if not src_dirs:
            return False
        src_dir = src_dirs[0]

        # 3. Определяем путь к go (должен быть уже установлен)
        go = _find_go_binary()
        if not go:
            return False

        # 4. go build (намеренно hardcoded GOARCH=amd64 — как в старом коде)
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        built = tmp / "webdav-tunnel"
        r = subprocess.run(
            [go, "build", "-o", str(built), "-ldflags", "-s -w", "."],
            capture_output=True, text=True,
            env=env, cwd=str(src_dir),
        )
        if r.returncode != 0:
            # go.sum может не покрывать все зависимости в офлайн-среде — добираем.
            offline_env = {**env, "GOSUMDB": "off"}
            subprocess.run(
                [go, "mod", "tidy"],
                capture_output=True, text=True,
                env=offline_env, cwd=str(src_dir),
            )
            r = subprocess.run(
                [go, "build", "-o", str(built), "-ldflags", "-s -w", "."],
                capture_output=True, text=True,
                env=env, cwd=str(src_dir),
            )
        if r.returncode != 0 or not built.exists():
            return False

        # 5. copy2 в /usr/local/bin/webdav-tunnel (без atomic-replace —
        # поведение 1-в-1 со старым кодом; TODO: можно добавить
        # _atomic_replace_binary из wdtt_packages если пользователь одобрит)
        shutil.copy2(str(built), str(_WEBDAV_BIN_PATH))
        _WEBDAV_BIN_PATH.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  Вспомогательные функции
# ============================================================================
def _find_go_binary() -> str | None:
    """Возвращает путь к go бинарнику (предпочитая /usr/local/bin/go).

    Локальная копия webdav_tunnel.py._check_go() — нужна чтобы post_install
    не зависел от импорта webdav_tunnel.py.
    """
    go_path = Path("/usr/local/bin/go")
    if go_path.exists():
        r = subprocess.run(
            [str(go_path), "version"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return str(go_path)

    import shutil as _shutil
    found = _shutil.which("go")
    if found:
        r = subprocess.run(
            [found, "version"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return found

    return None


# ============================================================================
#  PackageSpec — webdav-tunnel source tarball
# ============================================================================
WEBDAV_SOURCE_SPEC = PackageSpec(
    name="webdav-tunnel source",
    filename_builder=lambda: "webdav-tunnel-main.tar.gz",
    mirror_urls_builder=_webdav_source_mirror_urls,
    install_dests=[_INSTALL_TMP],              # [/tmp/webdav_packages] — placeholder
    manual_incoming_dir=_MANUAL_DIR,           # /root/
    min_size=_MIN_SOURCE_TARBALL_SIZE,         # 1 KB
    post_install=_post_install_webdav_source,  # extract + go build + copy2
)
