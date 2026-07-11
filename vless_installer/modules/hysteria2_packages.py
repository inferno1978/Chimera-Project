"""
vless_installer/modules/hysteria2_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для бинарника Hysteria2 (apernet/hysteria).

Используется двумя модулями:
  • hysteria2_exit_mgr.py::_install_h2_binary() — первичная установка
  • hysteria2_auto_update.py::h2_update_apply() — обновление

До миграции эти два модуля качали один и тот же бинарник двумя независимыми
путями:
  • exit_mgr: 3 зеркала (ghproxy.net + mirror.ghproxy.com) через subprocess
    curl, min_size=1 MB, ELF magic проверка.
  • auto_update: 1 прямой URL через curl, БЕЗ min_size, БЕЗ ELF magic
    (только запуск `version`).

Теперь оба используют единый HYSTERIA2_SPEC через fetch_package().

Особенности:
  • Бинарник — готовый ELF, без распаковки (в отличие от dnscrypt tar.gz).
  • post_install делает: ELF magic проверка → atomic-replace в H2_BINARY
    (stop service → unlink → copy2 → restart) — повторяет логику из
    старого _install_h2_binary / h2_update_apply.
  • arch подставляется через filename_kwargs: fetch_package(HYSTERIA2_SPEC,
    arch="amd64").
  • tag="latest" по умолчанию (всегда последний релиз) — но может быть
    передан конкретный "app/v2.9.3" если caller его знает.

install_dests = [/usr/local/bin] — это H2_BINARY.parent из hysteria2_common.
manual_incoming_dir = /root/ — не совпадает с install_dests, assert проходит.

Точки входа:
    from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# H2_BINARY из hysteria2_common = Path("/usr/local/bin/hysteria").
# install_dests = [/usr/local/bin] — директория, post_install ставит
# бинарник с именем "hysteria" (не "hysteria-linux-amd64").
_H2_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
# /root/ != /usr/local/bin — assert в __post_init__ проходит.
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "hysteria" (без архитектуры в имени).
# Скачанный файл называется "hysteria-linux-amd64", но post_install ставит
# его как /usr/local/bin/hysteria (так H2_BINARY определён в hysteria2_common).
_H2_DEST_FILENAME = "hysteria"

# Имя systemd-сервиса для atomic-replace логики.
_H2_SERVICE_NAME = "hysteria-server"

# Минимальный размер Hysteria2 бинарника.
# Реальный размер: ~20-30 MB (Go-бинарник с QUIC/TLS).
# 1 MB — нижний порог, отлавливает HTML-страницы 404 (раньше в exit_mgr было
# 1 MB, в auto_update — ничего).
_MIN_H2_BINARY_SIZE = 1_000_000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _hysteria2_mirror_urls(
    filename: str,
    tag: str = "latest",
    arch: str = "amd64",
    **kw,
) -> list[str]:
    """Собирает URL для Hysteria2 через hysteria2_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла конструируется из arch внутри
    get_hysteria2_mirrors().
    """
    return get_hysteria2_mirrors(tag=tag, arch=arch)


# ============================================================================
#  post_install — ELF magic проверка + atomic-replace в H2_BINARY
# ============================================================================
def _post_install_hysteria2(src: Path, install_dests: list[Path]) -> bool:
    """Копирует готовый ELF-бинарник в install_dests/hysteria с atomic-replace.

    Шаги:
      1. Проверка ELF magic (первые 4 байта == b'\\x7fELF') — защита от
         усечённых/HTML-загрузок, которые прошли min_size проверку.
      2. RUNTIME-проверка (не путать с ELF magic): запускаем скачанный
         бинарник с `version` subcommand. Если returncode != 0 — файл
         битый/несовместимый, возвращаем False БЕЗ удаления старого.
         Это критическая защита от регрессии: раньше (до Wave 3)
         h2_update_apply проверял запуск ДО замены; после миграции
         проверка ушла в post_install, но только ELF magic недостаточен —
         файл может пройти magic-check и быть битым. Теперь runtime-проверка
         снова на месте, и защищает ОБА вызова: _install_h2_binary
         (первичная установка) и h2_update_apply (обновление).
      3. Atomic-replace /usr/local/bin/hysteria:
         - systemctl stop hysteria-server (если активен — защита от ETXTBSY)
         - unlink старый бинарник (если есть)
         - copy2 нового
         - chmod 0o755
         - systemctl start hysteria-server (если был активен)

    Параметры:
      src:           Скачанный/ручной файл (готовый ELF-бинарник
                     hysteria-linux-{arch}).
      install_dests: Куда копировать (обычно [/usr/local/bin]).
                     Бинарник ставится как {install_dest}/hysteria.

    Возвращает:
      True если скопировано. False если файл не ELF, не запускается, или
      копирование упало — даёт fetch_package шанс попробовать следующее
      зеркало. ВАЖНО: при False старый бинарник НЕ трогается.
    """
    # 1. Проверка ELF magic (быстрая, дешёвая)
    try:
        with src.open("rb") as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            return False
    except Exception:
        return False

    # 2. RUNTIME-проверка: запускаем бинарник с `version` ДО замены.
    # Это защищает от битых/несовместимых бинарников которые прошли ELF
    # magic-check. Если returncode != 0 — возвращаем False, старый
    # бинарник не трогаем, fetch_package пробует следующее зеркало.
    try:
        # Копируем во временный файл с правом исполнения для проверки.
        # Нельзя chmod сам src — он может быть в /root/ (ручное размещение)
        # или в /tmp/_download_mgr_* (сетевое скачивание).
        import tempfile as _tmpmod
        verify_tmp = Path(_tmpmod.mktemp(suffix="_h2_verify"))
        shutil.copy2(str(src), str(verify_tmp))
        verify_tmp.chmod(0o755)
        try:
            r = subprocess.run(
                [str(verify_tmp), "version"],
                capture_output=True, timeout=15, check=False,
            )
        finally:
            verify_tmp.unlink(missing_ok=True)
        if r.returncode != 0:
            # Бинарник не запускается — НЕ трогаем старый, возвращаем False.
            return False
    except Exception:
        # Если не удалось провести runtime-проверку (например, нет прав на
        # исполнение в tempdir) — отказываемся от замены, возвращаем False.
        # Это безопаснее чем ставить непроверенный бинарник.
        return False

    # 3. Atomic-replace в install_dests[0]/hysteria (только после успешной
    # runtime-проверки — старый бинарник гарантированно не тронут если
    # новый битый).
    if not install_dests:
        return False
    dest_dir = install_dests[0]
    dest = dest_dir / _H2_DEST_FILENAME

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Проверяем активность сервиса (только если service file существует)
        _svc_was_active = False
        try:
            _chk = subprocess.run(
                ["systemctl", "is-active", "--quiet", _H2_SERVICE_NAME],
                capture_output=True, check=False,
            )
            _svc_was_active = (_chk.returncode == 0)
        except Exception:
            pass

        if _svc_was_active:
            try:
                subprocess.run(
                    ["systemctl", "stop", _H2_SERVICE_NAME],
                    capture_output=True, check=False,
                )
            except Exception:
                pass

        # unlink + copy (атомарная замена)
        if dest.exists():
            try:
                dest.unlink()
            except Exception:
                pass
        shutil.copy2(str(src), str(dest))
        dest.chmod(0o755)

        if _svc_was_active:
            try:
                subprocess.run(
                    ["systemctl", "start", _H2_SERVICE_NAME],
                    capture_output=True, check=False,
                )
            except Exception:
                pass

        return True
    except Exception:
        return False


# ============================================================================
#  PackageSpec — Hysteria2 binary
# ============================================================================
HYSTERIA2_SPEC = PackageSpec(
    name="Hysteria2",
    filename_builder=lambda arch, **kw: f"hysteria-linux-{arch}",
    mirror_urls_builder=_hysteria2_mirror_urls,
    install_dests=_H2_INSTALL_DESTS,            # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_H2_BINARY_SIZE,               # 1 MB
    post_install=_post_install_hysteria2,       # ELF check + atomic-replace
)
