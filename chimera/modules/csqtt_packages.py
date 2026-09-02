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
        if r and r.returncode == 0 and _RUST_VERSION in r.stdout:
            return True
        # Если версия не та — переустанавливаем
        print(f"[INFO] Нужен Rust {_RUST_VERSION}, переустанавливаю...")

    # Устанавливаем через rustup
    print("[INFO] Устанавливаю Rust toolchain через rustup...")
    print(f"[INFO] Это может занять 1-3 минуты (скачивание ~150 MB)...")
    try:
        r = subprocess.run(
            ["bash", "-c",
             "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
             "sh -s -- -y --default-toolchain {} --profile minimal".format(_RUST_VERSION)],
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
    """Собирает CSQTT сервер из исходников."""
    import tarfile

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

    # 2. Находим директорию с исходниками
    csqtt_dir = None
    for item in extract_dir.iterdir():
        if item.is_dir() and item.name.startswith("csqtt-"):
            # v74.2 (csqtt-layout-fix): upstream amurcanov/csqtt переименовал
            # серверную директорию csqtt-uring → rust-server (проверено на
            # архиве csqtt-main.tar.gz 734601 байт от 02.09: в корне
            # rust-client/ + rust-server/, папки csqtt-uring больше нет).
            # Оба варианта поддерживаются — старые локально скачанные архивы
            # тоже собираются.
            for sub in ("rust-server", "csqtt-uring"):
                cand = item / sub
                if cand.is_dir():
                    csqtt_dir = cand
                    break
            break

    if not csqtt_dir or not csqtt_dir.exists():
        print("[ERR] Директория сервера CSQTT не найдена "
              "(rust-server / csqtt-uring)")
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

    # 3. Проверяем/устанавливаем Rust
    print("[INFO] Проверяю/устанавливаю Rust toolchain...")
    try:
        if not _ensure_rust_toolchain():
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

    # 7. Находим собранный binary
    built_bin = csqtt_dir / "target" / target / "release" / "csqtt"
    if not built_bin.exists():
        # Пробуем дефолтный путь
        built_bin = csqtt_dir / "target" / "release" / "csqtt"
    if not built_bin.exists():
        print("[ERR] Binary не найден после сборки")
        print(f"[ERR] Искал в: {csqtt_dir}/target/{target}/release/csqtt")
        print(f"[ERR] И в:     {csqtt_dir}/target/release/csqtt")
        # Покажем что реально есть в target/
        target_dir = csqtt_dir / "target"
        if target_dir.exists():
            print(f"[ERR] Содержимое target/:")
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
