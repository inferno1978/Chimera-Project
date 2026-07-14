"""
chimera/modules/wdtt_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для исходников qWDTT (SpaceNeuroX/proxy-turn-vk-android).

Используется wdtt.py для скачивания source-tarball'а и сборки wdtt-server
бинарника. До миграции wdtt.py делал это ad-hoc через
urllib.request.urlretrieve + tar + go build + atomic-replace.

Особенности post_install:
  • Скачанный файл — tar.gz архив исходников, НЕ бинарник.
  • post_install делает:
      1. tar -xzf (распаковка во временную директорию)
      2. Поиск директории proxy-turn-vk-android-*
      3. go mod tidy (с GOSUMDB=off fallback — go.sum не в репозитории)
      4. go build -o wdtt-server -ldflags "-s -w" ./server.go
         (env: CGO_ENABLED=0, GOOS=linux, GOARCH=amd64 — как в старом коде)
      5. Atomic-replace /usr/local/bin/wdtt-server:
         - stop wdtt service если активен (защита от ETXTBSY)
         - unlink старый бинарник
         - copy2 нового
         - chmod 0o755
         - restart service если был активен
      6. cleanup временной директории

  • Go toolchain должен быть установлен ДО вызова fetch_package(WDTT_SOURCE_SPEC)
    — вызывающий код (wdtt.py._build_wdtt_server) сначала вызывает
    _ensure_go(), который при необходимости делает
    fetch_package(GO_TOOLCHAIN_SPEC, ...). Это разделение ответственности:
    WDTT_SOURCE_SPEC.post_install только собирает, не устанавливает Go.

install_dests = [/tmp/wdtt_packages] — временная директория, post_install
игнорирует её и ставит бинарник в /usr/local/bin/wdtt-server. Это нужно
только для PackageSpec.__post_init__ assert (manual_dir != install_dests):
manual_dir = /root/, install_dests = [/tmp/wdtt_packages] — коллизии нет.

Точки входа:
    from chimera.modules.wdtt_packages import WDTT_SOURCE_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.wdtt_mirrors import get_wdtt_source_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# install_dests — временная директория (post_install игнорирует её).
# /root/ НЕ должен совпадать с этим путём — PackageSpec инвариант.
_INSTALL_TMP = Path("/tmp/wdtt_packages")

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Целевой путь для собранного бинарника (используется в post_install).
_WDTT_BIN_PATH = Path("/usr/local/bin/wdtt-server")
_WDTT_SERVICE_NAME = "wdtt"
_WDTT_SERVICE_FILE = Path("/etc/systemd/system/wdtt.service")

# Минимальный размер source-tarball'а.
# Реальный размер: ~50-200 KB (Go-проект с исходниками, без vendor/).
# 1000 байт (1 KB) — нижний порог, отлавливает HTML-страницы 404.
_MIN_SOURCE_TARBALL_SIZE = 1000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _wdtt_source_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для исходников qWDTT через wdtt_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (proxy-turn-vk-android-master.tar.gz).
    """
    return get_wdtt_source_mirrors()


# ============================================================================
#  post_install — распаковка + go build + atomic-replace
# ============================================================================
def _post_install_wdtt_source(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает source-tarball, собирает wdtt-server, atomic-replaces
    существующий /usr/local/bin/wdtt-server.

    Полная репликация логики из старого wdtt.py._build_wdtt_server:
      1. tar -xzf во временную директорию
      2. Поиск proxy-turn-vk-android-* директории
      3. go mod tidy (с GOSUMDB=off fallback — go.sum отсутствует в репо)
      4. go build -o wdtt-server -ldflags "-s -w" ./server.go
         env: CGO_ENABLED=0, GOOS=linux, GOARCH=amd64 (как в старом коде —
         намеренно hardcoded amd64, см. комментарий в wdtt.py)
      5. Atomic-replace:
         - systemctl stop wdtt (если активен — защита от ETXTBSY)
         - unlink старый бинарник
         - copy2 + chmod 0o755
         - systemctl start wdtt (если был активен)
      6. cleanup временной директории

    Go toolchain должен быть установлен ДО этого вызова — вызывающий код
    отвечает за _ensure_go().

    Возвращает True при успехе, False при любой ошибке (даёт fetch_package
    шанс попробовать следующее зеркало — хотя для source-tarball это
    малополезно, т.к. ошибка обычно в сборке, а не в скачивании).
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
        src_dirs = list(tmp.glob("proxy-turn-vk-android-*"))
        if not src_dirs:
            return False
        src_dir = src_dirs[0]

        # 3. Определяем путь к go (должен быть уже установлен)
        go = _find_go_binary()
        if not go:
            return False

        # 4. go mod tidy (с GOSUMDB=off fallback — go.sum отсутствует в репо)
        r = subprocess.run(
            [go, "mod", "tidy"],
            capture_output=True, text=True,
            env=dict(os.environ),
            cwd=str(src_dir),
        )
        if r.returncode != 0:
            # Запасной путь — на серверах без доступа к sumdb/proxy.
            offline_env = {**os.environ, "GOSUMDB": "off"}
            r2 = subprocess.run(
                [go, "mod", "tidy"],
                capture_output=True, text=True,
                env=offline_env,
                cwd=str(src_dir),
            )
            if r2.returncode != 0:
                return False

        # 5. go build (намеренно hardcoded GOARCH=amd64 — как в старом коде)
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        built = tmp / "wdtt-server"
        r = subprocess.run(
            [go, "build", "-o", str(built),
             "-ldflags", "-s -w", "./server.go"],
            capture_output=True, text=True,
            env=env, cwd=str(src_dir),
        )
        if r.returncode != 0 or not built.exists():
            return False

        # 6. Atomic-replace /usr/local/bin/wdtt-server
        _atomic_replace_binary(built, _WDTT_BIN_PATH, _WDTT_SERVICE_NAME,
                               _WDTT_SERVICE_FILE)

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

    Локальная копия wdtt.py._check_go() — нужна чтобы post_install не зависел
    от импорта wdtt.py (который импортирует turn_packages, который импортирует
    download_manager — потенциальная циклическая зависимость).
    """
    go_path = Path("/usr/local/bin/go")
    if go_path.exists():
        r = subprocess.run(
            [str(go_path), "version"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return str(go_path)

    # Fallback на PATH
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


def _atomic_replace_binary(
    built: Path,
    bin_path: Path,
    service_name: str,
    service_file: Path,
) -> None:
    """Атомарная замена бинарника работающего сервиса.

    Реплицирует логику из wdtt.py._build_wdtt_server (lines 542-562):
      1. Если service_file существует и сервис активен — останавливаем.
      2. unlink старый бинарник (если есть).
      3. copy2 нового.
      4. chmod 0o755.
      5. Если сервис был активен — запускаем снова.

    Зачем stop/unlink вместо прямой перезаписи:
      shutil.copy2() на работающий процесс вызывает [Errno 26] Text file
      busy — Linux запрещает перезаписывать исполняемый файл напрямую.
      Правильный способ: удалить старый файл (unlink), затем скопировать
      новый — или остановить сервис, скопировать, потом запустить снова.
    """
    import subprocess as _sp

    _svc_was_active = False
    if service_file.exists():
        _chk = _sp.run(
            ["systemctl", "is-active", "--quiet", service_name],
            capture_output=True, check=False,
        )
        _svc_was_active = (_chk.returncode == 0)
        if _svc_was_active:
            _sp.run(
                ["systemctl", "stop", service_name],
                capture_output=True, check=False,
            )

    # unlink + copy (атомарная замена)
    if bin_path.exists():
        try:
            bin_path.unlink()
        except Exception:
            pass
    shutil.copy2(str(built), str(bin_path))
    bin_path.chmod(0o755)

    if _svc_was_active:
        _sp.run(
            ["systemctl", "start", service_name],
            capture_output=True, check=False,
        )


# ============================================================================
#  PackageSpec — qWDTT source tarball
# ============================================================================
WDTT_SOURCE_SPEC = PackageSpec(
    name="qWDTT source",
    filename_builder=lambda **kw: "proxy-turn-vk-android-master.tar.gz",
    mirror_urls_builder=_wdtt_source_mirror_urls,
    install_dests=[_INSTALL_TMP],              # [/tmp/wdtt_packages] — placeholder
    manual_incoming_dir=_MANUAL_DIR,           # /root/
    min_size=_MIN_SOURCE_TARBALL_SIZE,         # 1 KB
    post_install=_post_install_wdtt_source,    # extract + go build + atomic-replace
)
