"""
chimera/modules/backup_registry.py
───────────────────────────────────────────────────────────────────────────────
Единая АВТОМАТИЧЕСКИ РАСШИРЯЕМАЯ система бэкапа/восстановления всех протоколов.

ГЛАВНОЕ СВОЙСТВО — APPEND-FREE для новых протоколов:
  Никакого жёстко заданного списка модулей, который нужно пополнять при
  добавлении нового протокола. Список протоколов определяется динамически
  через pkgutil.iter_modules(chimera.modules.__path__) → импорт каждого
  модуля → вызов get_backup_paths() если функция определена.

КОНВЕНЦИЯ (договорённость об имени функции):
  Любой модуль в chimera/modules/, который хочет участвовать в общем
  бэкапе/восстановлении, определяет на уровне модуля:

    def get_backup_paths() -> list[tuple[Path, str]]:
        \"\"\"Возвращает [(реальный_путь_на_диске, имя_в_архиве), ...] —
        всё необходимое для восстановления протокола БЕЗ переиздания
        пользовательских ключей/секретов. Пустой список, если протокол
        не установлен/файлы не существуют — НЕ бросать исключение
        никогда, любая внутренняя ошибка = пустой список + tolerant
        пропуск.\"\"\"

  Модули БЕЗ get_backup_paths() тихо пропускаются (это норма — большинство
  из 214 модулей chimera/modules/ не являются протоколами и не имеют
  конфиг-файлов для бэкапа).

БЕЗОПАСНОСТЬ:
  • Любая ошибка импорта/вызова у конкретного модуля — тихий skip
    (try/except Exception: continue), не прерывает сбор для остальных.
  • Дедупликация по реальному пути (Path.resolve()) на случай, если
    два модуля случайно укажут один и тот же файл.
  • Timeout-guard через threading с join(timeout=N) — на случай, если
    в БУДУЩЕМ какой-то новый модуль случайно получит тяжёлую операцию
    на уровне импорта (сетевой запрос, sleep и т.п.). Один плохой
    модуль не может подвесить весь процесс бэкапа навсегда.

ИСПОЛЬЗОВАНИЕ:
  from chimera.modules.backup_registry import discover_backup_paths

  # В точках экспорта:
  paths = discover_backup_paths()  # [(Path, archive_name), ...]
  for src, arcname in paths:
      ...  # добавить в tar-архив

КЭШИРОВАНИЕ:
  Намеренно НЕ кэшируется между вызовами процесса — протоколы могут
  быть установлены/удалены между запусками бэкапа. Скан ~1 секунды на
  214 модулей — оптимизация не нужна.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib
import pkgutil
import threading
import time
from pathlib import Path
from typing import Optional


# ── Константы ─────────────────────────────────────────────────────────────────
#: Общий бюджет на сбор путей из ВСЕХ модулей. Если какой-то модуль
#: (обычно при импорте) зависнет — поток прерывается по таймауту, и
#: сбор возвращает то, что успело собраться, с WARN в лог.
DEFAULT_TIMEOUT_SEC: float = 20.0


# ── Логирование (отложенный импорт ядра, как во всех модулях проекта) ─────────
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    return importlib.import_module("chimera._core")


def _log_warn(msg: str) -> None:
    """Логирует WARN в chimera.log через _core.log_to_file, если ядро доступно.

    Используется для: таймаутов, упавших модулей при сборе. Никогда не
    бросает исключение — если логирование недоступно, молчит.
    """
    try:
        core = _core_module()
        if hasattr(core, "log_to_file"):
            core.log_to_file("WARN", msg)
    except Exception:
        pass


# ── Worker для timeout-guard ──────────────────────────────────────────────────
def _discover_worker(result: list, errors: list) -> None:
    """Выполняется в отдельном потоке — собирает пути из всех модулей.

    result: список для накопления [(Path, arcname), ...] — мутируется.
    errors: список для накопления строк ошибок (для логирования) — мутируется.
    """
    import chimera.modules as _mods_pkg

    for mod_info in pkgutil.iter_modules(_mods_pkg.__path__):
        full_name = f"chimera.modules.{mod_info.name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as e:
            # Тихий skip — не роняем остальные 213 модулей
            errors.append(f"import {full_name}: {type(e).__name__}: {e}")
            continue

        get_paths = getattr(mod, "get_backup_paths", None)
        if get_paths is None:
            # Это норма — большинство модулей не являются протоколами
            # и не имеют get_backup_paths(). Просто пропускаем.
            continue

        try:
            paths = get_paths()
        except Exception as e:
            # Конвенция требует НЕ бросать исключение, но если автор
            # нового модуля нарушил договорённость — не роняем остальные.
            errors.append(f"get_backup_paths() in {full_name}: {type(e).__name__}: {e}")
            continue

        if not paths:
            continue

        # Валидация и нормализация каждой записи
        for entry in paths:
            try:
                if not isinstance(entry, (tuple, list)) or len(entry) != 2:
                    errors.append(f"{full_name}: malformed entry {entry!r}, expected (Path, str)")
                    continue
                src_path, arcname = entry
                src_path = Path(src_path)
                if not isinstance(arcname, str) or not arcname:
                    errors.append(f"{full_name}: malformed arcname {arcname!r}")
                    continue
                result.append((src_path, arcname))
            except Exception as e:
                errors.append(f"{full_name}: entry normalization error: {type(e).__name__}: {e}")
                continue


# ── Публичный API ─────────────────────────────────────────────────────────────
def discover_backup_paths(timeout_sec: Optional[float] = None) -> list[tuple[Path, str]]:
    """Сканирует chimera/modules/ через pkgutil.iter_modules, импортирует
    каждый модуль, вызывает get_backup_paths() если функция определена.

    Любая ошибка импорта/вызова у конкретного модуля — тихий skip
    (try/except Exception: continue), не прерывает сбор для остальных.
    Дедупликация по реальному пути (Path.resolve()) на случай, если
    два модуля случайно укажут один и тот же файл.

    Args:
        timeout_sec: общий бюджет на сбор из ВСЕХ модулей. None = DEFAULT_TIMEOUT_SEC.
                     Если истёк — возвращает то, что успело собраться, + WARN в лог.

    Returns:
        list of (Path, str) — дедуплицированный список (src_path, arcname).
        Порядок не гарантирован (детерминирован только в пределах запуска).
        Гарантируется: каждый src_path уникален по Path.resolve().
    """
    if timeout_sec is None:
        timeout_sec = DEFAULT_TIMEOUT_SEC

    result: list[tuple[Path, str]] = []
    errors: list[str] = []

    worker = threading.Thread(
        target=_discover_worker,
        args=(result, errors),
        daemon=True,  # чтобы зависший поток не блокировал выход процесса
    )
    worker.start()
    worker.join(timeout=timeout_sec)

    if worker.is_alive():
        # Таймаут истёк, поток всё ещё работает — логируем и возвращаем
        # то, что успело собраться.
        _log_warn(
            f"backup_registry.discover_backup_paths: timeout {timeout_sec}s expired, "
            f"collected {len(result)} partial entries (one of chimera.modules.* "
            f"is likely hanging on import or in get_backup_paths())"
        )

    # Логируем ошибки сбора (не бросаем — пользователь видит бэкап частично)
    for err_msg in errors[:20]:  # ограничиваем лог
        _log_warn(f"backup_registry.discover: {err_msg}")
    if len(errors) > 20:
        _log_warn(f"backup_registry.discover: ... and {len(errors) - 20} more errors")

    # Дедупликация по реальному пути — если два модуля случайно указали
    # один и тот же файл, оставляем первое вхождение (детерминизм по
    # порядку обхода pkgutil, который в свою очередь детерминирован по
    # алфавиту имён модулей).
    seen: set[Path] = set()
    deduped: list[tuple[Path, str]] = []
    for src_path, arcname in result:
        try:
            resolved = src_path.resolve()
        except Exception:
            # Path.resolve() может бросить OSError на несуществующих путях
            # в редких случаях — используем не-resolved путь как ключ.
            resolved = src_path
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append((src_path, arcname))

    return deduped


# ── Утилиты для отчётности (используется в меню экспорта) ─────────────────────
def discover_backup_paths_verbose(timeout_sec: Optional[float] = None) -> tuple[list[tuple[Path, str]], list[str]]:
    """То же что discover_backup_paths, но также возвращает список ошибок
    сбора (для отображения пользователю в меню экспорта).

    Returns:
        (paths, errors) — paths как у discover_backup_paths(), errors —
        список человекочитаемых строк ошибок (пустой если всё OK).
    """
    if timeout_sec is None:
        timeout_sec = DEFAULT_TIMEOUT_SEC

    result: list[tuple[Path, str]] = []
    errors: list[str] = []

    worker = threading.Thread(
        target=_discover_worker,
        args=(result, errors),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=timeout_sec)

    timed_out = worker.is_alive()
    if timed_out:
        errors.append(
            f"timeout {timeout_sec}s expired — collected {len(result)} partial entries"
        )

    # Та же дедупликация
    seen: set[Path] = set()
    deduped: list[tuple[Path, str]] = []
    for src_path, arcname in result:
        try:
            resolved = src_path.resolve()
        except Exception:
            resolved = src_path
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append((src_path, arcname))

    return deduped, errors


__all__ = [
    "discover_backup_paths",
    "discover_backup_paths_verbose",
    "DEFAULT_TIMEOUT_SEC",
]
