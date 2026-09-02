#!/usr/bin/env python3
"""
chimera/modules/csqtt_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для скачивания и сборки CSQTT сервера.

CSQTT сервер — Rust проект (edition 2024, musl target).
Требует: rustup + Rust 1.97.1 + Zig + cargo-zigbuild.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from chimera.modules.download_manager import PackageSpec
from chimera.modules.csqtt_mirrors import get_csqtt_source_mirrors

_INSTALL_TMP = Path("/tmp/csqtt_packages")
_MANUAL_DIR  = Path("/root")

_CSQTT_BIN_PATH       = Path("/usr/local/bin/csqtt-server")
_CSQTT_SERVICE_NAME   = "csqtt"
_CSQTT_SERVICE_FILE   = Path("/etc/systemd/system/csqtt.service")
_MIN_SOURCE_TARBALL_SIZE = 1000   # 1 KB

# ── v76.1: ГОТОВЫЙ бинарь, собранный на ДРУГОЙ машине ────────────────────────
# Юзер, чей сервер не тянет Rust-сборку (OOM/слабый VPS), компилирует
# csqtt-server где-нибудь ещё, загружает файл на сервер (scp/WinSCP/SFTP)
# в одну из директорий ниже — и повторный запуск установки подхватывает
# бинарь АВТОМАТИЧЕСКИ, не предлагая сборку заново.
_MANUAL_BIN_DIRS = (
    Path("/root"),            # scp/WinSCP под root — дефолт
    Path("/tmp"),             # временные загрузки
    Path("/opt"),             # классика для ручного софта
    Path("/usr/local/src"),   # исходники/артефакты
)
_MANUAL_BIN_HOME = Path("/home")   # /home/<юзер>/csqtt-server (верхний уровень)
# Точные имена (приоритет), затем glob-шаблоны — cargo-zigbuild может дать
# имя с target-суффиксом: csqtt-server-x86_64-unknown-linux-musl
_MANUAL_BIN_EXACT = ("csqtt-server", "csqtt")
_MANUAL_BIN_GLOBS = ("csqtt-server*", "csqtt*server*", "csqtt_server*",
                     "csqtt-server-*.bin", "csqtt.bin")
# Суффиксы, которые бинарем быть не могут (архивы/тексты) — исключаем из
# кандидатов, чтобы не пугать юзера «нашёл файл, но он не ELF».
_MANUAL_BIN_BAD_SUFFIXES = {".gz", ".tgz", ".tar", ".xz", ".zip", ".bz2",
                            ".txt", ".md", ".json", ".sig", ".asc", ".sum",
                            ".sha256", ".py", ".sh", ".rs", ".toml"}
_MANUAL_BIN_MIN_SIZE = 1_000_000   # 1 MB: Rust-релиз с aws-lc-sys много больше
# ELF e_machine → архитектура (проверка «бинарь собран под этот сервер»)
_ELF_MACHINES = {62: "x86_64", 183: "aarch64", 40: "arm", 3: "x86",
                 243: "riscv64"}

# Rust toolchain
_RUST_VERSION = "1.97.1"
_RUST_TARGET  = "x86_64-unknown-linux-musl"

# v75 (upstream_updates): информация о последней сборке — заполняется
# _post_install_csqtt_source, читается upstream_updates._build_info()
# для state-файла /var/lib/chimera/upstream-updates.json:
#   tarball_sha256 — детект «зеркало отдало тот же архив»;
#   layout         — какой уровень probe сработал (диагностика дрейфа);
#   rust_required  — что потребовал upstream в Cargo.toml.
LAST_BUILD_INFO: Dict[str, Any] = {}

# Известные имена серверной директории (в порядке приоритета):
#   rust-server  — upstream с 02.09 (v74.2)
#   csqtt-uring  — старый layout (локальные архивы до переезда)
#   server       — возможное будущее имя (простая эвристика)
_KNOWN_SERVER_SUBDIRS = ("rust-server", "csqtt-uring", "server")


def _parse_cargo_toml(cargo: Path) -> Dict[str, Any]:
    """Мини-парсер Cargo.toml без внешних зависимостей: [package].name,
    [[bin]].name, rust-version. Терпим к комментариям и лишним секциям."""
    try:
        text = cargo.read_text(errors="replace")
    except Exception:
        return {}
    info: Dict[str, Any] = {}
    m = re.search(r'\[package\][^\[]*?^name\s*=\s*"([^"]+)"',
                  text, re.M | re.S)
    if m:
        info["package_name"] = m.group(1)
    bins = re.findall(r'\[\[bin\]\][^\[]*?^name\s*=\s*"([^"]+)"',
                      text, re.M | re.S)
    if bins:
        info["bin_names"] = bins
    m = re.search(r'^rust-version\s*=\s*"([^"]+)"', text, re.M)
    if m:
        info["rust_version"] = m.group(1)
    return info


def _probe_csqtt_layout(extract_dir: Path) -> Optional[Dict[str, Any]]:
    """v75: ищет серверный Rust-крейт CSQTT в распакованном архиве.

    Три уровня (вместо одного захардкоженного пути до v74.2, который
    ломался при каждом переименовании папки upstream):

      1. Канонический layout: <корень>/csqtt-*/{rust-server|csqtt-uring|server}
         с Cargo.toml внутри.
      2. Cargo.toml прямо в csqtt-*/ (upstream убрал вложенность).
      3. Future-proof: rglob("Cargo.toml") по всему дереву (глубина ≤ 3) —
         берём крейт по скорингу:
           +100  package_name == "csqtt"
           +60   package_name.startswith("csqtt") и не "client"
           +40   bin name "csqtt"
           +20   есть src/main.rs (бинарный крейт)
           −100 имя содержит "client" (rust-client — НЕ сервер!)

    Возвращает {"source_dir", "bin_names", "rust_required", "how"} | None.
    """
    def _mk(cargo_dir: Path, how: str) -> Dict[str, Any]:
        pi = _parse_cargo_toml(cargo_dir / "Cargo.toml")
        names = list(pi.get("bin_names", []))
        pkg = pi.get("package_name")
        if pkg and pkg not in names:
            names.append(pkg)
        if "csqtt" not in names:
            names.append("csqtt")       # легаси-кандидат (до v75)
        return {
            "source_dir": cargo_dir,
            "bin_names": names,
            "rust_required": pi.get("rust_version"),
            "how": how,
        }

    # ── Уровень 1: известные имена серверных поддиректорий ─────────────
    try:
        top_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]
    except Exception:
        return None
    for top in top_dirs:
        for sub in _KNOWN_SERVER_SUBDIRS:
            cand = top / sub
            if (cand / "Cargo.toml").is_file():
                return _mk(cand, f"known:{sub}")

    # ── Уровень 2: крейт прямо в корне архива ──────────────────────────
    for top in top_dirs:
        if (top / "Cargo.toml").is_file():
            pi = _parse_cargo_toml(top / "Cargo.toml")
            name = (pi.get("package_name") or "").lower()
            if name == "csqtt" or (name.startswith("csqtt")
                                   and "client" not in name):
                return _mk(top, "crate-at-root")

    # ── Уровень 3: future-proof rglob по дереву ────────────────────────
    scored = []
    try:
        cargos = [c for c in extract_dir.rglob("Cargo.toml")
                  if len(c.relative_to(extract_dir).parts) <= 3]
    except Exception:
        cargos = []
    for cargo in cargos:
        d = cargo.parent
        pi = _parse_cargo_toml(cargo)
        pkg = (pi.get("package_name") or "").lower()
        score = 0
        if "client" in pkg or "client" in d.name.lower():
            score -= 100
        if pkg == "csqtt":
            score += 100
        elif pkg.startswith("csqtt"):
            score += 60
        if "csqtt" in (pi.get("bin_names") or []):
            score += 40
        if (d / "src" / "main.rs").is_file():
            score += 20
        if score > 0:
            scored.append((score, d))
    if scored:
        scored.sort(key=lambda x: -x[0])
        return _mk(scored[0][1], f"rglob:{scored[0][0]}pts")

    return None


def _csqtt_source_mirror_urls(filename, **kw) -> list[str]:
    return get_csqtt_source_mirrors()


def _check_rust() -> str | None:
    """Проверяет наличие rustc, возвращает путь или None."""
    for p in ("/root/.cargo/bin/rustc", "/usr/local/bin/rustc"):
        if Path(p).exists():
            return p
    return shutil.which("rustc")


def _check_cargo() -> str | None:
    """Проверяет наличие cargo."""
    for p in ("/root/.cargo/bin/cargo", "/usr/local/bin/cargo"):
        if Path(p).exists():
            return p
    return shutil.which("cargo")


def _check_zig() -> str | None:
    """Проверяет наличие zig."""
    return shutil.which("zig")


def _ensure_rust_toolchain(version: Optional[str] = None) -> bool:
    """Устанавливает Rust через rustup, если не установлен.

    v75: version — требование upstream из Cargo.toml (rust-version).
    Берётся MAX(требование, пиннинг _RUST_VERSION): если upstream
    поднял минимальную версию, ставим её; если Cargo.toml молчит —
    остаётся проверенный пиннинг проекта.
    """
    wanted = _RUST_VERSION
    if version:
        try:
            a = tuple(int(p) for p in version.split(".")[:3])
            b = tuple(int(p) for p in _RUST_VERSION.split(".")[:3])
            if a > b:
                wanted = version
        except (ValueError, IndexError):
            pass

    # Гарантируем что /root/.cargo/bin в PATH для subprocess.run ниже.
    # Без этого _check_rust() может найти rustc в /root/.cargo/bin/rustc
    # (через Path.exists()), но subprocess.run(["rustc", ...]) упадёт с
    # FileNotFoundError, т.к. /root/.cargo/bin нет в $PATH.
    cargo_bin = Path("/root/.cargo/bin")
    if cargo_bin.exists():
        path_env = os.environ.get("PATH", "")
        if str(cargo_bin) not in path_env.split(":"):
            os.environ["PATH"] = f"{cargo_bin}:{path_env}"

    if _check_rust() and _check_cargo():
        # Проверяем версию
        try:
            r = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
        except FileNotFoundError:
            # _check_rust() нашёл путь, но в PATH его нет (или бинарник
            # битый). Пытаемся переустановить.
            print("[INFO] rustc найден, но не запускается — переустанавливаю...")
            r = None
        if r and r.returncode == 0 and wanted in r.stdout:
            return True
        # Если версия не та — переустанавливаем
        print(f"[INFO] Нужен Rust {wanted}, переустанавливаю...")

    # Устанавливаем через rustup
    print("[INFO] Устанавливаю Rust toolchain через rustup...")
    print(f"[INFO] Это может занять 1-3 минуты (скачивание ~150 MB)...")
    try:
        r = subprocess.run(
            ["bash", "-c",
             "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
             "sh -s -- -y --default-toolchain {} --profile minimal".format(wanted)],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        print(f"[ERR] rustup превысил timeout 300 сек (медленный интернет?)")
        return False
    except Exception as e:
        print(f"[ERR] rustup упал с исключением: {type(e).__name__}: {e}")
        return False

    if r.returncode != 0:
        print(f"[ERR] Не удалось установить Rust: {r.stderr[-500:]}")
        return False

    # Обновляем PATH после установки
    path_env = os.environ.get("PATH", "")
    if str(cargo_bin) not in path_env.split(":"):
        os.environ["PATH"] = f"{cargo_bin}:{path_env}"

    # Устанавливаем musl target
    print(f"[INFO] Добавляю target {_RUST_TARGET}...")
    try:
        r = subprocess.run(
            ["rustup", "target", "add", _RUST_TARGET],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(f"[ERR] rustup target add превысил timeout 120 сек")
        return False
    except Exception as e:
        print(f"[ERR] rustup target add упал: {type(e).__name__}: {e}")
        return False

    if r.returncode != 0:
        print(f"[ERR] Не удалось добавить target {_RUST_TARGET}: {r.stderr[-500:]}")
        return False

    # Финальная проверка — что rustc реально работает
    try:
        r = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[ERR] rustc установлен, но не запускается: {r.stderr}")
            return False
        print(f"[OK] Rust toolchain установлен: {r.stdout.strip()}")
    except FileNotFoundError:
        print(f"[ERR] Rust установлен, но rustc не в PATH. Перезапустите установку.")
        return False

    return True


def _ensure_zig() -> bool:
    """Устанавливает Zig, если не установлен."""
    if _check_zig():
        return True

    print("[INFO] Устанавливаю Zig...")
    # Скачиваем Zig с GitHub
    import urllib.request
    import tarfile
    import tempfile

    zig_version = "0.14.0"
    arch = subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip()
    arch_map = {"x86_64": "x86_64", "aarch64": "aarch64"}
    zig_arch = arch_map.get(arch, "x86_64")

    url = f"https://ziglang.org/download/{zig_version}/zig-linux-{zig_arch}-{zig_version}.tar.xz"
    tmp_dir = Path(tempfile.mkdtemp())
    tmp_tar = tmp_dir / "zig.tar.xz"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            tmp_tar.write_bytes(resp.read())
    except Exception as e:
        print(f"[ERR] Не удалось скачать Zig: {e}")
        return False

    # Распаковываем
    r = subprocess.run(
        ["tar", "-xf", str(tmp_tar), "-C", str(tmp_dir)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"[ERR] Не удалось распаковать Zig: {r.stderr}")
        return False

    # Копируем в /usr/local/bin
    zig_dir = tmp_dir / f"zig-linux-{zig_arch}-{zig_version}"
    zig_bin = zig_dir / "zig"
    if zig_bin.exists():
        shutil.copy2(zig_bin, "/usr/local/bin/zig")
        os.chmod("/usr/local/bin/zig", 0o755)
        # Копируем lib
        lib_dir = Path("/usr/local/lib/zig")
        if lib_dir.exists():
            shutil.rmtree(lib_dir)
        shutil.copytree(zig_dir / "lib", lib_dir)
        print("[OK] Zig установлен")
        return True

    print("[ERR] Zig binary не найден после распаковки")
    return False


def _ensure_cargo_zigbuild() -> bool:
    """Устанавливает cargo-zigbuild."""
    cargo = _check_cargo()
    if not cargo:
        return False

    env = dict(os.environ)
    env["PATH"] = f"/root/.cargo/bin:{env.get('PATH', '')}"

    r = subprocess.run(
        ["cargo", "install", "cargo-zigbuild", "--locked"],
        capture_output=True, text=True, env=env, timeout=600,
    )
    if r.returncode != 0:
        print(f"[ERR] Не удалось установить cargo-zigbuild: {r.stderr}")
        return False

    print("[OK] cargo-zigbuild установлен")
    return True


def _detect_arch() -> str:
    """Возвращает архитектуру для сборки."""
    r = subprocess.run(["uname", "-m"], capture_output=True, text=True)
    m = r.stdout.strip()
    arch_map = {
        "x86_64":  "x86_64",
        "amd64":   "x86_64",
        "aarch64": "aarch64",
        "arm64":   "aarch64",
    }
    return arch_map.get(m, "x86_64")


def _elf_arch(path: Path) -> Optional[str]:
    """Читает ELF-заголовок файла → архитектура ('x86_64'/'aarch64'/...).

    None = не ELF (нет magic \\x7fELF), файл короче заголовка, битый
    e_machine или неизвестная машина. Осознанно НЕ проверяем класс
    32/64-bit и endianness данных: e_machine достаточно, чтобы понять,
    запустится ли бинарь на этом сервере.
    """
    import struct
    try:
        with open(path, "rb") as f:
            hdr = f.read(20)
    except Exception:
        return None
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        return None
    ei_data = hdr[5]                # 1 = LE, 2 = BE
    fmt = ">" if ei_data == 2 else "<"
    try:
        machine = struct.unpack(fmt + "H", hdr[18:20])[0]
    except Exception:
        return None
    return _ELF_MACHINES.get(machine)


def _validate_manual_binary(path: Path) -> tuple:
    """Проверяет, что файл — рабочий ELF-бинарь под архитектуру СЕРВЕРА.

    Возвращает (ok, why): why — человекочитаемая причина отказа (для
    диагностики «нашёл файл, но он не подходит»).
    """
    try:
        size = path.stat().st_size
    except Exception as e:
        return False, f"не читается: {e}"
    if size < _MANUAL_BIN_MIN_SIZE:
        return False, (f"слишком маленький ({size} байт < "
                       f"{_MANUAL_BIN_MIN_SIZE})")
    arch = _elf_arch(path)
    if arch is None:
        return False, "не ELF-бинарь (нет magic)"
    host = _detect_arch()
    if arch != host:
        return False, (f"архитектура {arch} ≠ сервера {host} — "
                       f"на этом сервере не запустится")
    return True, f"ELF {arch}, {size} байт"


def _scan_manual_bin_candidates() -> list:
    """Все кандидаты «ручного бинаря» в порядке приоритета.

    Порядок: точные имена по директориям (в порядке _MANUAL_BIN_DIRS),
    затем glob-шаблоны по тем же директориям. Плюс /home/<юзер>/ —
    только файлы верхнего уровня (не бегаем по всему /home).

    /usr/local/bin/csqtt-server сюда НЕ входит — это место НАЗНАЧЕНИЯ,
    оно проверяется отдельно в install_manual_binary().
    """
    candidates: list = []
    dirs: list = [d for d in _MANUAL_BIN_DIRS if d.is_dir()]
    try:
        if _MANUAL_BIN_HOME.is_dir():
            dirs += [d for d in _MANUAL_BIN_HOME.iterdir()
                     if d.is_dir()]
    except (PermissionError, OSError):
        pass

    for d in dirs:
        for name in _MANUAL_BIN_EXACT:
            p = d / name
            try:
                if p.is_file() and p.suffix not in _MANUAL_BIN_BAD_SUFFIXES:
                    candidates.append(p)
            except (PermissionError, OSError):
                continue

    for d in dirs:
        for pattern in _MANUAL_BIN_GLOBS:
            try:
                for p in sorted(d.glob(pattern)):
                    if (p.is_file()
                            and p not in candidates
                            and p.suffix not in _MANUAL_BIN_BAD_SUFFIXES):
                        candidates.append(p)
            except (PermissionError, OSError):
                continue
    return candidates


def find_manual_binary() -> tuple:
    """Ищет ГОТОВЫЙ бинарь среди кандидатов (см. _scan_manual_bin_candidates).

    Возвращает (валидный_путь | None, [(путь, причина), ...]).
    Список отклонённых — для диагностики: юзер видит, ЧТО нашлось и
    ПОЧЕМУ не подошло (не ELF / чужая архитектура / слишком маленький).
    """
    rejects: list = []
    for cand in _scan_manual_bin_candidates():
        ok, why = _validate_manual_binary(cand)
        if ok:
            return cand, rejects
        rejects.append((cand, why))
    return None, rejects


def install_manual_binary(verbose: bool = True) -> bool:
    """v76.1: устанавливает ГОТОВЫЙ бинарь, загруженный юзером вручную.

    Приоритет:
      1. Ручные директории (_MANUAL_BIN_DIRS + /home/<юзер>/): файл
         csqtt-server / csqtt / csqtt-server-* с валидным ELF-заголовком
         под архитектуру сервера → атомарная установка в
         /usr/local/bin/csqtt-server. Сеть и исходники НЕ трогаем.
      2. Если ручного нет, но по месту назначения уже лежит ВАЛИДНЫЙ
         бинарь (юзер скопировал прямо в /usr/local/bin, или это
         «переустановить с сохранением» после прошлой установки) —
         считаем установленным, сборка не требуется.

    Валидация (см. _validate_manual_binary): ELF magic, архитектура
    e_machine == архитектура сервера, размер >= 1 MB. Это отсекает
    случайные файлы, архивы и бинари чужой архитектуры (собранный на
    M1 Mac aarch64-бинарь не молча ляжет на x86_64-VPS).

    Возвращает True только если бинарь УСТАНОВЛЕН (или уже на месте).
    False = ручного бинаря нет → вызывающий код идёт в сборку из
    исходников, как раньше.
    """
    found, rejects = find_manual_binary()

    if verbose and rejects:
        # Диагностика отклонённых кандидатов — ВСЕГДА (даже когда
        # валидного не нашлось): юзер, закинувший бинарь не той
        # архитектуры, должен видеть причину, а не молчаливое
        # «иду собирать из исходников».
        for rej_path, rej_why in rejects:
            print(f"[WARN]   {rej_path} отклонён: {rej_why}")

    if not found:
        # Кандидатов нет — проверяем, не лежит ли уже валидный бинарь
        # по месту назначения (частный случай: юзер сам скопировал в
        # /usr/local/bin, либо переустановка с сохранением).
        if _CSQTT_BIN_PATH.is_file():
            ok, why = _validate_manual_binary(_CSQTT_BIN_PATH)
            if ok:
                if verbose:
                    print(f"[OK] csqtt-server уже на месте: "
                          f"{_CSQTT_BIN_PATH} ({why}) — сборка не требуется")
                try:
                    _CSQTT_BIN_PATH.chmod(0o755)
                except Exception:
                    pass
                return True
        return False

    if verbose:
        try:
            size_mb = found.stat().st_size / (1024 * 1024)
            print(f"[OK] Найден готовый бинарь csqtt-server: {found} "
                  f"({size_mb:.1f} MB) — устанавливаю без сборки")
        except Exception:
            print(f"[OK] Найден готовый бинарь csqtt-server: {found} "
                  f"— устанавливаю без сборки")

    try:
        ok = _atomic_replace_binary(found, _CSQTT_BIN_PATH,
                                    _CSQTT_SERVICE_NAME,
                                    _CSQTT_SERVICE_FILE)
    except Exception as e:
        print(f"[ERR] Установка ручного бинаря упала: "
              f"{type(e).__name__}: {e}")
        return False
    if ok and verbose:
        print(f"[OK] Готовый бинарь установлен: {_CSQTT_BIN_PATH}")
    return ok


def print_manual_binary_hint() -> None:
    """v76.1: инструкция «как поставить готовый бинарь без сборки».

    Печатается в блоке ошибки установки CSQTT: юзер, чей сервер не
    тянет сборку, собирает бинарь на другой машине, загружает на
    сервер — и повторный запуск установки подхватывает его сам.
    """
    print()
    print("[HINT] Сборка на этом сервере не тянет? Есть путь без сборки:")
    print("  1. Соберите csqtt-server на другой машине (Linux, ТА ЖЕ")
    print("     архитектура, что и сервер):")
    print("       git clone https://github.com/amurcanov/csqtt")
    print("       cd csqtt/rust-server && cargo build --release")
    print("       # бинарь: target/release/csqtt")
    print("       # (кросс-сборка без установленного Rust на сервере:")
    print("       #  cargo zigbuild --release --target x86_64-unknown-linux-musl)")
    print("  2. Загрузите бинарь на сервер (scp/WinSCP) под именем")
    print("     csqtt-server в любую из директорий:")
    for d in _MANUAL_BIN_DIRS:
        print(f"         {d}/")
    print(f"         {_MANUAL_BIN_HOME}/<юзер>/")
    print("  3. Повторите установку CSQTT — установщик сам найдёт бинарь")
    print("     (проверит ELF-заголовок и архитектуру) и НЕ будет")
    print("     предлагать сборку заново.")


def _atomic_replace_binary(built: Path, bin_path: Path,
                           service_name: str, service_file: Path) -> bool:
    """Атомарно заменяет binary (останавливает сервис если активен)."""
    was_active = False
    r = subprocess.run(["systemctl", "is-active", service_name],
                       capture_output=True, text=True, check=False)
    if r.returncode == 0 and r.stdout.strip() == "active":
        was_active = True
        subprocess.run(["systemctl", "stop", service_name],
                       capture_output=True, check=False)

    try:
        if bin_path.exists():
            bin_path.unlink()
    except Exception:
        pass

    try:
        shutil.copy2(built, bin_path)
        bin_path.chmod(0o755)
    except Exception as e:
        print(f"[ERR] Не удалось скопировать binary: {e}")
        return False

    if was_active:
        subprocess.run(["systemctl", "start", service_name],
                       capture_output=True, check=False)

    return True


def _ensure_swap_and_pick_jobs() -> int:
    """Anti-OOM: измеряет RAM+swap, при необходимости создаёт /swapfile,
    возвращает количество параллельных задач для cargo (-j N).

    Логика:
      • Читаем /proc/meminfo (MemAvailable + SwapFree).
      • Если SwapFree < 1 GB и /swapfile не существует — создаём swap
        на 2 GB (требует 2 GB свободного места на корневом разделе).
      • Возвращаем -j:
        - 1, если (RAM + swap) < 2 GB — самый безопасный режим
        - 2, иначе (хватит для параллельной сборки 2 крейтов)
    """
    try:
        meminfo = Path("/proc/meminfo").read_text()
        avail_kb = 0
        swap_free_kb = 0
        swap_total_kb = 0
        for line in meminfo.splitlines():
            if line.startswith("MemAvailable:"):
                avail_kb = int(line.split()[1])
            elif line.startswith("SwapTotal:"):
                swap_total_kb = int(line.split()[1])
            elif line.startswith("SwapFree:"):
                swap_free_kb = int(line.split()[1])

        ram_gb = avail_kb / (1024 * 1024)
        swap_gb = swap_free_kb / (1024 * 1024)
        print(f"[INFO] RAM available: {ram_gb:.2f} GB, swap free: {swap_gb:.2f} GB")

        # Если swap < 1 GB — пробуем создать /swapfile на 2 GB
        if swap_total_kb < 1024 * 1024:  # < 1 GB total swap
            swapfile = Path("/swapfile")
            if not swapfile.exists():
                # Проверяем свободное место на /
                df = subprocess.run(["df", "-B1", "/"], capture_output=True, text=True)
                try:
                    free_bytes = int(df.stdout.splitlines()[1].split()[3])
                    if free_bytes >= 2 * 1024 * 1024 * 1024:  # >= 2 GB свободно
                        print("[INFO] Создаю /swapfile на 2 GB (anti-OOM для сборки)...")
                        cmds = [
                            ["fallocate", "-l", "2G", str(swapfile)],
                            ["chmod", "600", str(swapfile)],
                            ["mkswap", str(swapfile)],
                            ["swapon", str(swapfile)],
                        ]
                        ok = True
                        for c in cmds:
                            r = subprocess.run(c, capture_output=True, text=True)
                            if r.returncode != 0:
                                print(f"[WARN] {c[0]} не удалось: {r.stderr.strip()[:200]}")
                                ok = False
                                break
                        if ok:
                            # Добавляем в /etc/fstab для persist после ребута
                            fstab = Path("/etc/fstab")
                            if fstab.exists():
                                fstab_text = fstab.read_text()
                                if "/swapfile" not in fstab_text:
                                    fstab.write_text(fstab_text.rstrip() + "\n/swapfile none swap sw 0 0\n")
                            print("[OK] /swapfile создан и включён (2 GB)")
                            swap_gb = 2.0
                        else:
                            # Чистим частично созданный swapfile
                            if swapfile.exists():
                                swapfile.unlink()
                except (ValueError, IndexError):
                    pass
            else:
                # swapfile уже существует но не активен — пробуем включить
                r = subprocess.run(["swapon", str(swapfile)], capture_output=True, text=True)
                if r.returncode == 0:
                    print("[OK] /swapfile активирован")
                    swap_gb = 2.0

        total_gb = ram_gb + swap_gb
        if total_gb < 2.0:
            print(f"[INFO] Всего {total_gb:.2f} GB — использую -j 1 (safest)")
            return 1
        else:
            print(f"[INFO] Всего {total_gb:.2f} GB — использую -j 2")
            return 2
    except Exception as e:
        print(f"[WARN] Не удалось определить RAM/swap: {e}, использую -j 1 (safest)")
        return 1


def _post_install_csqtt_source(src: Path, install_dests: list[Path]) -> bool:
    """Собирает CSQTT сервер из исходников.

    v75: директория исходников и имя бинарника определяются layout-probe
    (_probe_csqtt_layout), а не захардкожены — переименование папки
    upstream (инцидент v74.2: csqtt-uring → rust-server) больше не
    ломает установку. Требуемая версия Rust читается из Cargo.toml.
    """
    import tarfile

    # v75: хэш скачанного tarball — для upstream_updates (детект
    # «зеркало отдало прежний архив» + диагностика дрейфа layout).
    LAST_BUILD_INFO.clear()
    try:
        h = hashlib.sha256()
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        LAST_BUILD_INFO["tarball_sha256"] = h.hexdigest()
    except Exception:
        pass

    # 1. Распаковываем
    print("[INFO] Распаковываю tarball...")
    extract_dir = Path("/tmp/csqtt_build")
    shutil.rmtree(extract_dir, ignore_errors=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(src, "r:gz") as tf:
            tf.extractall(path=extract_dir)
    except Exception as e:
        print(f"[ERR] Распаковка не удалась: {type(e).__name__}: {e}")
        return False

    # 2. v75: layout-probe — ищем серверный крейт (3 уровня, см.
    #    _probe_csqtt_layout). До v74.2 путь был захардкожен и ломался
    #    при переименованиях upstream.
    probe = _probe_csqtt_layout(extract_dir)
    if not probe:
        print("[ERR] Серверный крейт CSQTT не найден в архиве "
              "(rust-server / csqtt-uring / Cargo.toml)")
        try:
            top = list(extract_dir.iterdir())
            if top:
                print(f"[ERR]   {top[0].name}/ → "
                      f"{sorted(c.name for c in top[0].iterdir() if c.is_dir())}")
            else:
                print("[ERR]   (архив распакован, но пуст)")
        except Exception:
            pass
        return False

    csqtt_dir: Path = probe["source_dir"]
    bin_names = probe["bin_names"]
    LAST_BUILD_INFO["layout"] = probe["how"]
    if probe.get("rust_required"):
        LAST_BUILD_INFO["rust_required"] = probe["rust_required"]
    print(f"[INFO] Layout: {probe['how']} → {csqtt_dir}")

    # 3. Проверяем/устанавливаем Rust (v75: версия из Cargo.toml)
    print("[INFO] Проверяю/устанавливаю Rust toolchain...")
    try:
        if not _ensure_rust_toolchain(probe.get("rust_required")):
            print("[ERR] Rust toolchain недоступен")
            return False
    except Exception as e:
        print(f"[ERR] Rust toolchain упал с исключением: {type(e).__name__}: {e}")
        return False

    # 4. Проверяем/устанавливаем Zig
    print("[INFO] Проверяю/устанавливаю Zig...")
    try:
        if not _ensure_zig():
            print("[ERR] Zig недоступен")
            return False
    except Exception as e:
        print(f"[ERR] Zig упал с исключением: {type(e).__name__}: {e}")
        return False

    # 5. Проверяем/устанавливаем cargo-zigbuild
    print("[INFO] Проверяю/устанавливаю cargo-zigbuild...")
    try:
        if not _ensure_cargo_zigbuild():
            print("[ERR] cargo-zigbuild недоступен")
            return False
    except Exception as e:
        print(f"[ERR] cargo-zigbuild упал с исключением: {type(e).__name__}: {e}")
        return False

    # 6. Собираем
    env = dict(os.environ)
    env["PATH"] = f"/root/.cargo/bin:{env.get('PATH', '')}"
    env["CARGO_HOME"] = "/root/.cargo"

    arch = _detect_arch()
    target = f"{arch}-unknown-linux-musl"

    # Anti-OOM: aws-lc-sys (криптография) при компиляции одного .c файла
    # жрёт до 1.5-2 GB RAM одним процессом rustc/cc. На VPS с < 2 GB RAM
    # без swap это = гарантированный SIGKILL от OOM killer.
    #
    # Стратегия:
    #   1. Замеряем доступный RAM + swap.
    #   2. Если swap маленький (< 1 GB) — автоматически создаём /swapfile
    #      на 2 GB (если есть свободное место на диске).
    #   3. Выбираем -j по итоговому объёму памяти:
    #      < 1.5 GB → -j 1 (только один rustc за раз, самый безопасный)
    #      1.5-3 GB → -j 2
    #      > 3 GB   → -j 2 (всё равно -j 2, т.к. musl-build тяжелее обычного)
    print("[INFO] Анализирую RAM/swap для anti-OOM...")
    try:
        jobs = _ensure_swap_and_pick_jobs()
    except Exception as e:
        print(f"[WARN] _ensure_swap_and_pick_jobs упал: {type(e).__name__}: {e}")
        print(f"[INFO] Fallback: использую -j 1 (safest)")
        jobs = 1
    timeout = 2400 if jobs == 1 else 1800   # -j 1 → 40 мин, -j 2 → 30 мин

    print(f"[INFO] Собираю CSQTT для {target}...")
    print(f"[INFO] cargo -j {jobs} — anti-OOM (aws-lc-sys ест до 2 GB RAM/процесс)")
    print(f"[INFO] Это может занять 5-20 минут. Не прерывайте!")
    try:
        r = subprocess.run(
            ["cargo", "zigbuild", "--release", "--target", target, "-j", str(jobs)],
            cwd=str(csqtt_dir),
            capture_output=True, text=True,
            env=env, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[ERR] Сборка превысила timeout {timeout} сек ({timeout // 60} мин)")
        print(f"[ERR] Возможные причины:")
        print(f"      - VPS слишком медленный (1 vCPU)")
        print(f"      - Медленный диск (HDD вместо SSD)")
        print(f"      - Сетевые паузы при скачивании crates с crates.io")
        print(f"[ERR] Попробуйте запустить direct-build скрипт для повторной попытки:")
        print(f"      bash <(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/scripts/csqtt-direct-build.sh)")
        return False
    except Exception as e:
        print(f"[ERR] cargo zigbuild упал с исключением: {type(e).__name__}: {e}")
        return False

    if r.returncode != 0:
        # Показываем больше stderr для диагностики
        stderr_tail = r.stderr[-1500:] if r.stderr else "(пусто)"
        print(f"[ERR] Сборка не удалась (exit code {r.returncode})")
        print(f"[ERR] Последние 1500 символов stderr:")
        print(stderr_tail)
        return False

    # 7. v75: Находим собранный binary — кандидаты из probe (имя пакета
    #    / [[bin]] / легаси «csqtt»), оба возможных пути target/.
    built_bin = None
    for name in bin_names:
        for cand in (csqtt_dir / "target" / target / "release" / name,
                     csqtt_dir / "target" / "release" / name):
            if cand.exists():
                built_bin = cand
                break
        if built_bin:
            break
    if not built_bin:
        print(f"[ERR] Binary не найден после сборки")
        print(f"[ERR] Искал имена: {bin_names} в:")
        print(f"[ERR]   {csqtt_dir}/target/{target}/release/")
        print(f"[ERR]   {csqtt_dir}/target/release/")
        # Покажем что реально есть в target/
        target_dir = csqtt_dir / "target"
        if target_dir.exists():
            print("[ERR] Содержимое target/:")
            for p in target_dir.rglob("csqtt*"):
                print(f"  {p}")
        return False

    # 8. Атомарно заменяем
    print("[INFO] Устанавливаю binary...")
    try:
        if not _atomic_replace_binary(built_bin, _CSQTT_BIN_PATH,
                                       _CSQTT_SERVICE_NAME, _CSQTT_SERVICE_FILE):
            return False
    except Exception as e:
        print(f"[ERR] Установка binary упала: {type(e).__name__}: {e}")
        return False

    print(f"[OK] CSQTT собран и установлен: {_CSQTT_BIN_PATH}")

    # 9. Очистка
    shutil.rmtree(extract_dir, ignore_errors=True)

    return True


CSQTT_SOURCE_SPEC = PackageSpec(
    name="CSQTT source",
    filename_builder=lambda **kw: "csqtt-main.tar.gz",
    mirror_urls_builder=_csqtt_source_mirror_urls,
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_SOURCE_TARBALL_SIZE,
    post_install=_post_install_csqtt_source,
)
