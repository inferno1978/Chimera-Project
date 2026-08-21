#!/usr/bin/env python3
"""
chimera/modules/csqtt_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для скачивания и сборки CSQTT сервера.

CSQTT сервер — Rust проект (edition 2024, musl target).
Требует: rustup + Rust 1.97.1 + Zig + cargo-zigbuild.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.csqtt_mirrors import get_csqtt_source_mirrors

_INSTALL_TMP = Path("/tmp/csqtt_packages")
_MANUAL_DIR  = Path("/root")

_CSQTT_BIN_PATH       = Path("/usr/local/bin/csqtt-server")
_CSQTT_SERVICE_NAME   = "csqtt"
_CSQTT_SERVICE_FILE   = Path("/etc/systemd/system/csqtt.service")
_MIN_SOURCE_TARBALL_SIZE = 1000   # 1 KB

# Rust toolchain
_RUST_VERSION = "1.97.1"
_RUST_TARGET  = "x86_64-unknown-linux-musl"


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


def _ensure_rust_toolchain() -> bool:
    """Устанавливает Rust через rustup, если не установлен."""
    if _check_rust() and _check_cargo():
        # Проверяем версию
        r = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
        if r.returncode == 0 and _RUST_VERSION in r.stdout:
            return True
        # Если версия не та — переустанавливаем
        print(f"[INFO] Нужен Rust {_RUST_VERSION}, проверяю...")

    # Устанавливаем через rustup
    print("[INFO] Устанавливаю Rust toolchain через rustup...")
    r = subprocess.run(
        ["bash", "-c",
         "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
         "sh -s -- -y --default-toolchain {} --profile minimal".format(_RUST_VERSION)],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        print(f"[ERR] Не удалось установить Rust: {r.stderr}")
        return False

    # Добавляем cargo в PATH
    cargo_bin = Path("/root/.cargo/bin")
    env = dict(os.environ)
    env["PATH"] = f"{cargo_bin}:{env.get('PATH', '')}"

    # Устанавливаем musl target
    r = subprocess.run(
        ["rustup", "target", "add", _RUST_TARGET],
        capture_output=True, text=True, env=env, timeout=120,
    )
    if r.returncode != 0:
        print(f"[ERR] Не удалось добавить target {_RUST_TARGET}: {r.stderr}")
        return False

    print("[OK] Rust toolchain установлен")
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


def _post_install_csqtt_source(src: Path, install_dests: list[Path]) -> bool:
    """Собирает CSQTT сервер из исходников."""
    import tarfile

    # 1. Распаковываем
    extract_dir = Path("/tmp/csqtt_build")
    shutil.rmtree(extract_dir, ignore_errors=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(src, "r:gz") as tf:
            tf.extractall(path=extract_dir)
    except Exception as e:
        print(f"[ERR] Распаковка не удалась: {e}")
        return False

    # 2. Находим директорию с исходниками
    csqtt_dir = None
    for item in extract_dir.iterdir():
        if item.is_dir() and item.name.startswith("csqtt-"):
            csqtt_dir = item / "csqtt-uring"
            break

    if not csqtt_dir or not csqtt_dir.exists():
        print("[ERR] Директория csqtt-uring не найдена")
        return False

    # 3. Проверяем/устанавливаем Rust
    if not _ensure_rust_toolchain():
        print("[ERR] Rust toolchain недоступен")
        return False

    # 4. Проверяем/устанавливаем Zig
    if not _ensure_zig():
        print("[ERR] Zig недоступен")
        return False

    # 5. Проверяем/устанавливаем cargo-zigbuild
    if not _ensure_cargo_zigbuild():
        print("[ERR] cargo-zigbuild недоступен")
        return False

    # 6. Собираем
    env = dict(os.environ)
    env["PATH"] = f"/root/.cargo/bin:{env.get('PATH', '')}"
    env["CARGO_HOME"] = "/root/.cargo"

    arch = _detect_arch()
    target = f"{arch}-unknown-linux-musl"

    print(f"[INFO] Собираю CSQTT для {target}...")
    print(f"[INFO] -j 2 — ограничение параллельности (anti-OOM для VPS с малым RAM)")
    r = subprocess.run(
        ["cargo", "zigbuild", "--release", "--target", target, "-j", "2"],
        cwd=str(csqtt_dir),
        capture_output=True, text=True,
        env=env, timeout=1800,
    )
    if r.returncode != 0:
        print(f"[ERR] Сборка не удалась: {r.stderr[-500:]}")
        return False

    # 7. Находим собранный binary
    built_bin = csqtt_dir / "target" / target / "release" / "csqtt"
    if not built_bin.exists():
        # Пробуем дефолтный путь
        built_bin = csqtt_dir / "target" / "release" / "csqtt"
    if not built_bin.exists():
        print("[ERR] Binary не найден после сборки")
        return False

    # 8. Атомарно заменяем
    if not _atomic_replace_binary(built_bin, _CSQTT_BIN_PATH,
                                   _CSQTT_SERVICE_NAME, _CSQTT_SERVICE_FILE):
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
