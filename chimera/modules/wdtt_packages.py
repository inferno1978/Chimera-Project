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
      4. go build -o wdtt-server -ldflags "-s -w" — ./server (новый layout
         upstream от 02.09, v74.2) с фолбэком на ./server.go (старые архивы)
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

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

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

# Дефолтная требуемая версия Go (когда go.mod недоступен до скачивания).
# v74.2: поднята 1.21.0 → 1.25.0 (upstream go.mod требует 1.25.0).
_GO_REQUIRED_DEFAULT = "1.25.0"

# v75 (upstream_updates): информация о последней сборке — заполняется
# _post_install_wdtt_source, читается upstream_updates._build_info():
#   tarball_sha256 — детект «зеркало отдало тот же архив»;
#   layout         — какой набор build-таргетов сработал;
#   go_required    — версия Go, потребованная go.mod upstream.
LAST_BUILD_INFO: Dict[str, Any] = {}


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
#  v75: layout-probe — build-таргеты и требования go.mod читаются из архива
# ============================================================================
def _go_mod_requirement(src_dir: Path) -> str:
    """Версия Go из директивы 'go X.Y[.Z]' в go.mod распакованных исходников.

    Фолбэк _GO_REQUIRED_DEFAULT — если go.mod не читается. Именно так
    «изменение требований апстрима» (инцидент v74.2: go 1.21 → 1.25)
    перестаёт быть сюрпризом: требование читается из upstream-файла,
    а не захардкожено в Chimera.
    """
    gomod = src_dir / "go.mod"
    if gomod.exists():
        try:
            m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)",
                          gomod.read_text(errors="replace"), re.M)
            if m:
                return m.group(1)
        except Exception:
            pass
    return _GO_REQUIRED_DEFAULT


def _go_version_tuple(go: str) -> Optional[tuple]:
    """(major, minor, patch) установленного go; None если не определился."""
    try:
        r = subprocess.run([go, "version"], capture_output=True, text=True)
        m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", r.stdout or "")
        if m:
            return tuple(int(p) for p in m.group(1).split("."))
    except Exception:
        pass
    return None


def _probe_wdtt_build_targets(src_dir: Path) -> List[str]:
    """v75: упорядоченные go-build таргеты для wdtt-server.

    Три уровня (вместо двух захардкоженных до v75):
      1. Известные layout'ы (в порядке приоритета):
           ./server      — модульный layout upstream с 02.09 (v74.2)
           ./server.go   — корневой файл (старые архивы)
      2. Корневые *.go с 'package main' → файловые таргеты
         (main.go / любой root-файл main-пакета — будущие переименования).
      3. Поддиректории 1-го уровня с 'package main' (есть main.go или
         любой .go с func main) → "./{sub}"; включая ./cmd/*/
         (стандартная go-конвенция будущих версий upstream).

    Возврат — уникальный список; go build пробует их по очереди
    (первый успешный выигрывает — как в v74.2, но список шире).
    """
    targets: List[str] = []

    def _add(t: str) -> None:
        if t not in targets:
            targets.append(t)

    # ── Уровень 1: известные имена ────────────────────────────────────
    if (src_dir / "server").is_dir() and (src_dir / "server" / "main.go").is_file():
        _add("./server")
    elif (src_dir / "server").is_dir():
        _add("./server")
    if (src_dir / "server.go").is_file():
        _add("./server.go")

    # ── Уровень 2: корневые *.go с package main ──────────────────────
    try:
        root_go = sorted(src_dir.glob("*.go"))
    except Exception:
        root_go = []
    main_root_files = []
    for gf in root_go:
        try:
            if "package main" in gf.read_text(errors="replace")[:2000]:
                main_root_files.append(gf.name)
        except Exception:
            continue
    if main_root_files and len(main_root_files) == len(root_go) and root_go:
        _add(".")            # все корневые .go — один main-пакет
    for name in main_root_files:
        _add(f"./{name}")

    # ── Уровень 3: поддиректории с package main / cmd/* ────────────
    try:
        subs = sorted(d for d in src_dir.iterdir() if d.is_dir()
                      and not d.name.startswith("."))
    except Exception:
        subs = []
    for d in subs:
        if d.name in ("server", "cmd"):
            continue          # server уже в уровне 1; cmd — ниже
        try:
            gos = list(d.glob("*.go"))
        except Exception:
            continue
        if not gos:
            continue
        is_main = False
        for gf in gos[:5]:
            try:
                txt = gf.read_text(errors="replace")
            except Exception:
                continue
            if "package main" in txt[:2000] and "func main(" in txt:
                is_main = True
                break
        if is_main:
            _add(f"./{d.name}")
    # cmd/ подпакеты (go-конвенция)
    cmd_dir = src_dir / "cmd"
    if cmd_dir.is_dir():
        try:
            for d in sorted(cmd_dir.iterdir()):
                if d.is_dir() and (d / "main.go").is_file():
                    _add(f"./cmd/{d.name}")
        except Exception:
            pass

    return targets


def _ensure_go_meets(required: str) -> Optional[str]:
    """Гарантирует что установленный Go >= required; при нехватке ставит
    свежий Go через download_manager (GO_TOOLCHAIN_SPEC — зеркала + /root/).

    Политика:
      • Go отсутствует → ставим latest (go.dev, фолбэк go{required}).
      • Go есть, версия >= required → используем как есть.
      • Go есть, версия < required → ставим свежий (драйф требований
        upstream, инцидент v74.2: go 1.21 при требовании 1.25).
      • Go есть, но версия не определилась (экзотика) → НЕ качаем
        60 MB вслепую: используем существующий, реальную пригодность
        покажет go build с диагностикой.

    Возвращает путь к go или None. Это локальная копия логики
    wdtt.py._ensure_go (нельзя импортировать wdtt.py — циклическая
    зависимость через turn_packages → download_manager).
    """
    go = _find_go_binary()
    if go:
        cur = _go_version_tuple(go)
        if cur is None:
            print(f"  [INFO] Версия установленного Go не определилась — "
                  f"пробую собрать имеющимся (требование: {required})")
            return go
        req = _ver3(required)
        if cur >= req:
            return go
        print(f"  [INFO] Установленный Go {cur} < требуемого {required} — "
              f"обновляю toolchain...")

    # Ставим свежий Go: latest с go.dev, фолбэк go{required}.
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC

    version = ""
    try:
        import urllib.request
        with urllib.request.urlopen("https://go.dev/VERSION?m=text",
                                   timeout=15) as resp:
            version = resp.read().decode("utf-8", "replace").splitlines()[0].strip()
        if not version.startswith("go"):
            version = f"go{required}"
    except Exception:
        version = f"go{required}"

    import subprocess as _sp
    arch_raw = _sp.run(["uname", "-m"], capture_output=True, text=True)
    arch = "arm64" if (arch_raw.stdout or "").strip() == "aarch64" else "amd64"

    print(f"  [INFO] Устанавливаю {version} ({arch}, через download_manager)...")
    if not fetch_package(GO_TOOLCHAIN_SPEC, version=version, arch=arch):
        return None

    go = _find_go_binary()
    if go:
        cur = _go_version_tuple(go)
        if cur is None or cur >= _ver3(required):
            return go
    return None


def _ver3(v: str) -> tuple:
    """"1.25" / "1.25.0" → (1, 25, 0) — кортеж для сравнения версий."""
    parts = [int(p) for p in v.split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)

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
      4. go build -o wdtt-server -ldflags "-s -w" — ./server (новый layout
         upstream от 02.09, v74.2) с фолбэком на ./server.go (старые архивы)
         env: CGO_ENABLED=0, GOOS=linux, GOARCH=amd64 (как в старом коде —
         намеренно hardcoded amd64, см. комментарий в wdtt.py)
      5. Atomic-replace:
         - systemctl stop wdtt (если активен — защита от ETXTBSY)
         - unlink старый бинарник
         - copy2 + chmod 0o755
         - systemctl start wdtt (если был активен)
      6. cleanup временной директории

    Go toolchain должен быть установлен ДО этого вызова — вызывающий код
    отвечает за _ensure_go(). НО v75: если go.mod распакованных исходников
    требует БОЛЬШЕ, чем установлено (драйф требований upstream), post_install
    сам догоняет toolchain через download_manager (_ensure_go_meets) —
    именно так класс бага v74.2 («go.mod requires go >= 1.25.0» при
    установленном 1.21) закрыт навсегда.

    Возвращает True при успехе, False при любой ошибке (даёт fetch_package
    шанс попробовать следующее зеркало — хотя для source-tarball это
    малополезно, т.к. ошибка обычно в сборке, а не в скачивании).
    """
    import os

    # v75: хэш tarball — для upstream_updates (детект «зеркало отдало
    # прежний архив» + диагностика).
    LAST_BUILD_INFO.clear()
    try:
        h = hashlib.sha256()
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        LAST_BUILD_INFO["tarball_sha256"] = h.hexdigest()
    except Exception:
        pass

    tmp = Path(tempfile.mkdtemp())
    try:
        # 1. Распаковка
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск директории с исходниками.
        #    v75: кроме канонического proxy-turn-vk-android-* — фолбэк на
        #    ЛЮБУЮ верхнюю директорию с go.mod (если upstream переименует
        #    репозиторий, имя папки в архиве изменится, а сборка выживет).
        src_dirs = list(tmp.glob("proxy-turn-vk-android-*"))
        if not src_dirs:
            try:
                src_dirs = [d for d in tmp.iterdir()
                            if d.is_dir() and (d / "go.mod").is_file()]
            except Exception:
                src_dirs = []
        if not src_dirs:
            return False
        src_dir = src_dirs[0]

        # 3. v75: требование go.mod → гарантируем подходящий Go.
        #    _ensure_go_meets сам ставит свежий Go через download_manager,
        #    если установленный старее требуемого.
        required = _go_mod_requirement(src_dir)
        LAST_BUILD_INFO["go_required"] = required
        go = _ensure_go_meets(required)
        if not go:
            print(f"  [ERR] Go {required}+ недоступен — установка прервана")
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

        # 5. v75: build-таргеты — layout-probe (_probe_wdtt_build_targets):
        #    известные ./server и ./server.go (v74.2) + корневые main-файлы
        #    + поддиректории package main + cmd/*. Будущие переезды upstream
        #    подхватываются автоматически, первый успешный таргет выигрывает.
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        built = tmp / "wdtt-server"
        build_targets = _probe_wdtt_build_targets(src_dir)
        if not build_targets:
            print("  [ERR] В архиве нет main-пакета Go (server/, server.go, "
                  "package main) — layout не распознан")
            return False
        built_ok = False
        for target in build_targets:
            r = subprocess.run(
                [go, "build", "-o", str(built),
                 "-ldflags", "-s -w", target],
                capture_output=True, text=True,
                env=env, cwd=str(src_dir),
            )
            if r.returncode == 0 and built.exists():
                LAST_BUILD_INFO["build_target"] = target
                built_ok = True
                break
        if not built_ok:
            print(f"  [ERR] go build не удался (пробовал: {build_targets})")
            return False

        # 6. Atomic-replace /usr/local/bin/wdtt-server
        _atomic_replace_binary(built, _WDTT_BIN_PATH, _WDTT_SERVICE_NAME,
                               _WDTT_SERVICE_FILE)
        LAST_BUILD_INFO["layout"] = LAST_BUILD_INFO.get("build_target", "")

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
