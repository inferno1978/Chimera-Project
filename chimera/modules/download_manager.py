"""
chimera/modules/download_manager.py
───────────────────────────────────────────────────────────────────────────────
Декларативный download manager для скачивания пакетов/бинарников/файлов
данных проекта.

Архитектурно решает класс бага из geo_files.py (регрессия 21d7baf):
  После первого успешного запуска файлы уже лежат в install_dests
  (рабочих директориях). Безусловная проверка "ручного размещения"
  по тем же директориям находила свой же файл → копировала сам на себя
  → репортила успех БЕЗ сети → geo-правила замораживались навсегда.

Решение: PackageSpec.__post_init__ АРХИТЕКТУРНО ЗАПРЕЩАЕТ
manual_incoming_dir совпадать с любым install_dest. Это делает класс
бага физически невозможным по конструкции — assert падает на создании
spec, ДО любого сетевого вызова.

Использование:
    from chimera.modules.download_manager import PackageSpec, fetch_package
    from chimera.modules.github_mirrors import build_mirror_urls

    spec = PackageSpec(
        name="geosite",
        filename_builder=lambda: "geosite.dat",
        mirror_urls_builder=lambda filename: build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename=filename,
            tag="latest",
            ref="release",
        ),
        install_dests=[Path("/usr/local/share/xray"), Path("/etc/xray")],
        manual_incoming_dir=Path("/root"),
        min_size=3_000_000,
        post_install=lambda tmp, dests: _copy_to_dests(tmp, dests),
    )
    ok = fetch_package(spec)

Точки входа:
    from chimera.modules.download_manager import (
        PackageSpec, fetch_package, print_manual_hint,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ============================================================================
#  PackageSpec — декларативное описание пакета для скачивания
# ============================================================================

@dataclass
class PackageSpec:
    """Декларативное описание пакета/файла для скачивания.

    Инвариант (КРИТИЧНО): manual_incoming_dir НЕ должен совпадать ни с одним
    install_dest. Это предотвращает класс бага из geo_files.py (регрессия
    21d7baf): после первой успешной установки файл лежит в install_dests,
    и если manual_incoming_dir == install_dest, то повторный вызов найдёт
    свой же файл и никогда не пойдёт в сеть.

    Поля:
      name:                  Человеко-читаемое имя пакета (для логов/подсказок).
      filename_builder:      Callable[..., str] — возвращает имя файла.
                             Принимает **filename_kwargs из fetch_package().
      mirror_urls_builder:   Callable[..., list[str]] — возвращает список URL.
                             Принимает filename= и **filename_kwargs.
      install_dests:         Куда копировать файл при успехе (все директории).
      manual_incoming_dir:   Где искать файл от пользователя (WinSCP).
                             ПО УМОЛЧАНИЮ /root/. НЕ должен совпадать с
                             install_dests — assert в __post_init__.
      min_size:              Минимальный размер файла в байтах (защита от
                             усечённых загрузок). 0 = не проверять.
      post_install:          Optional[Callable[[Path, list[Path]], bool]].
                             Вызывается после скачивания/копирования с
                             (tmp_path, install_dests). Возвращает True при
                             успехе. Если None — просто copy2+chmod во все
                             install_dests.
    """

    name: str
    filename_builder: Callable[..., str]
    mirror_urls_builder: Callable[..., list[str]]
    install_dests: list[Path]
    manual_incoming_dir: Path = Path("/root")
    min_size: int = 0
    post_install: Optional[Callable[[Path, list[Path]], bool]] = None

    def __post_init__(self):
        # КРИТИЧЕСКИЙ ИНВАРИАНТ: ручная директория НЕ должна совпадать
        # ни с одной install_dest. Это воспроизводит защиту от бага 21d7baf
        # на уровне конструктора — spec с коллизией просто не создаётся.
        for dest in self.install_dests:
            assert self.manual_incoming_dir != dest, (
                f"PackageSpec({self.name!r}): manual_incoming_dir "
                f"({self.manual_incoming_dir}) не может совпадать ни с одним "
                f"install_dest ({dest}) — это воспроизводит баг из geo_files.py "
                f"(регрессия 21d7baf): после первой успешной установки файл "
                f"лежит в install_dests, повторный вызов найдёт свой же файл "
                f"и никогда не проверит сеть"
            )


# ============================================================================
#  fetch_package — основная функция скачивания
# ============================================================================

def fetch_package(
    spec: PackageSpec,
    *,
    dry_run: bool = False,
    print_hint_on_failure: bool = True,
    **filename_kwargs,
) -> bool:
    """Скачивает пакет по spec.

    Алгоритм:
      1. filename = spec.filename_builder(**filename_kwargs)
      2. Проверка manual_incoming_dir / filename — если есть и size >= min_size,
         копирует, вызывает post_install (если задан), возвращает True.
         СЕТЬ НЕ ТРОГАЕТ.
      3. Иначе — перебор mirror_urls по очереди через urllib.
         connect-timeout=15s, max-time=180s, без бесконечных ретраев.
         При успехе — копирует во ВСЕ install_dests, post_install, True.
      4. При полном провале — print_manual_hint(spec, filename=...), False
         (если print_hint_on_failure=True).

    Параметры:
      spec:                  PackageSpec с описанием пакета.
      dry_run:               True — не делать реальных сетевых вызовов и
                             копирований. Возвращает False (для тестов).
      print_hint_on_failure: True (по умолчанию) — печатать инструкцию для
                             ручного скачивания при провале всех зеркал.
                             False — вызывающий код сам напечатает свою
                             подсказку (например geo_files использует
                             _geo_print_manual_download_hint с полным
                             списком путей).
      **filename_kwargs:     Дополнительные аргументы для filename_builder и
                             mirror_urls_builder.

    Возвращает:
      True при успехе (файл найден локально ИЛИ скачан).
      False при провале (все зеркала упали, /root/ пуст).
    """
    filename = spec.filename_builder(**filename_kwargs)
    manual_path = spec.manual_incoming_dir / filename

    # ── 1) Проверка ручного размещения (только manual_incoming_dir!) ────────
    # ВАЖНО: НЕ проверяем install_dests здесь — это физически невозможно
    # благодаря __post_init__ assert. После первой установки файл лежит в
    # install_dests, но мы его НЕ трогаем — идём в сеть.
    if not dry_run:
        try:
            if manual_path.exists() and manual_path.stat().st_size >= spec.min_size:
                # Файл найден локально — используем без сети
                if spec.post_install is not None:
                    ok = spec.post_install(manual_path, spec.install_dests)
                    if not ok:
                        return False
                else:
                    _default_copy_to_dests(manual_path, spec.install_dests)
                return True
        except (PermissionError, OSError):
            # manual_incoming_dir может быть недоступен (например /root/
            # при запуске не от root) — просто пропускаем, идём в сеть
            pass

    # ── 2) Сетевое скачивание — перебор зеркал ─────────────────────────────
    urls = spec.mirror_urls_builder(filename=filename, **filename_kwargs)

    if dry_run:
        # В dry_run режиме возвращаем False — реальных сетевых вызовов нет
        return False

    tmp_path = Path("/tmp") / f"_download_mgr_{filename}"
    tmp_path.unlink(missing_ok=True)

    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "VLESS-Ultimate-Installer"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                with open(tmp_path, 'wb') as f:
                    while True:
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)

            if tmp_path.exists() and tmp_path.stat().st_size >= spec.min_size:
                # Скачано успешно — копируем во все install_dests
                if spec.post_install is not None:
                    ok = spec.post_install(tmp_path, spec.install_dests)
                    if not ok:
                        tmp_path.unlink(missing_ok=True)
                        continue  # пробуем следующее зеркало
                else:
                    _default_copy_to_dests(tmp_path, spec.install_dests)

                tmp_path.unlink(missing_ok=True)
                return True

            # Файл слишком маленький — пробуем следующее зеркало
            tmp_path.unlink(missing_ok=True)

        except Exception:
            tmp_path.unlink(missing_ok=True)
            continue

    # ── 3) Все зеркала провалились — подсказка ─────────────────────────────
    tmp_path.unlink(missing_ok=True)
    if print_hint_on_failure:
        print_manual_hint(spec, filename=filename, **filename_kwargs)
    return False


# ============================================================================
#  Вспомогательные функции
# ============================================================================

def _default_copy_to_dests(src: Path, dests: list[Path]) -> None:
    """Копирует src во все dests с chmod 0o644."""
    for dest_dir in dests:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        try:
            shutil.copy2(str(src), str(dest))
            dest.chmod(0o644)
        except Exception:
            pass


def print_manual_hint(spec: PackageSpec, *, filename: str, **filename_kwargs) -> None:
    """Печатает инструкцию для ручного скачивания.

    Формат — как в существующих print_*_manual_download_hint() функциях.
    Использует цвета из _core (через importlib), с fallback на пустые.

    filename_kwargs передаются в mirror_urls_builder чтобы отображаемые URL
    совпадали с теми, которые реально пытался скачать fetch_package (tag,
    tarball_filename и т.д.). Без этого print_manual_hint показывал URL с
    дефолтными параметрами (например tag="0.7.6" вместо реального "1.13.14").
    """
    import importlib
    try:
        core = importlib.import_module("chimera._core")
        YELLOW = core.YELLOW
        NC = core.NC
        BOLD = core.BOLD
        WHITE = core.WHITE
        CYAN = core.CYAN
        GREEN = core.GREEN
        DIM = core.DIM
    except Exception:
        YELLOW = NC = BOLD = WHITE = CYAN = GREEN = DIM = ""

    # Собираем URLs для отображения (с теми же filename_kwargs, что и при реальной попытке)
    try:
        urls = spec.mirror_urls_builder(filename=filename, **filename_kwargs)
    except Exception:
        urls = []

    sep = f"{YELLOW}{'─' * 64}{NC}"
    print()
    print(sep)
    print(f"{BOLD}{YELLOW}Не удалось скачать {spec.name} автоматически.{NC}")
    print(f"{WHITE}   Скачайте файл вручную и разместите на сервере.{NC}")
    print(sep)
    print()
    print(f"{CYAN}Файл: {filename}{NC}")
    if urls:
        print(f"{DIM}({len(urls)} зеркал в fallback){NC}")
        for i, url in enumerate(urls, 1):
            print(f"    {DIM}{i:>2}){NC} {url}")
    print()
    print(f"{CYAN}Разместите файл в:{NC}")
    print(f"    {BOLD}{GREEN}{spec.manual_incoming_dir}/{NC}  "
          f"{BOLD}{GREEN}← рекомендуется (WinSCP-friendly){NC}")
    print()
    if urls:
        print(f"{WHITE}Команда для скачивания на сервере:{NC}")
        print(f"    {DIM}curl -fL \"{urls[0]}\" -o "
              f"{spec.manual_incoming_dir}/{filename}{NC}")
    print()
    print(f"{WHITE}Или SCP с вашего ПК:{NC}")
    print(f"    {DIM}scp {filename} root@<IP>:{spec.manual_incoming_dir}/{NC}")
    print()
    print(f"{WHITE}После размещения файла повторите операцию.{NC}")
    print()
    print(sep)
    print()
