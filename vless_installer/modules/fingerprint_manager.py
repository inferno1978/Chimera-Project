"""
fingerprint_manager.py
======================
Централизованное управление TLS Fingerprint (FP) для Xray/VLESS.

Отвечает за:
- Полный актуальный список FP, поддерживаемых Xray-core.
- Интерактивный выбор FP пользователем во время установки.
- Валидацию ввода и безопасный fallback.

Интегрируется в _core.py минимально и точечно:
  - PARAM_FINGERPRINT хранит выбранный FP для текущей сессии установки.
  - prompt_fingerprint() вызывается из prompt_parameters() и ручного ввода нод.
"""

from __future__ import annotations

__all__ = [
    "XRAY_FP_LIST",
    "DEFAULT_FP",
    "prompt_fingerprint",
]

# ---------------------------------------------------------------------------
#  Полный список FP, поддерживаемых Xray-core (utls + встроенные варианты).
#  Источник: https://xtls.github.io/config/transport.html#tlsobject
#  Порядок: популярные первыми для удобства выбора.
# ---------------------------------------------------------------------------
XRAY_FP_LIST: list[str] = [
    "chrome",       # Google Chrome (наиболее распространён)
    "firefox",      # Mozilla Firefox
    "safari",       # Apple Safari (desktop)
    "ios",          # Safari on iOS / iPadOS
    "android",      # Android / okhttp
    "edge",         # Microsoft Edge
    "360",          # 360 Browser (Qihoo)
    "qq",           # QQ Browser (Tencent)
    "random",       # случайный из реальных браузеров (выбирает Xray при старте)
    "randomized",   # рандомизированный при каждом хендшейке (uTLS randomized)
    "none",         # не использовать uTLS (стандартный Go TLS)
]

DEFAULT_FP: str = "chrome"

# Сопоставление номера → имени FP
_FP_MENU: dict[str, str] = {str(i): fp for i, fp in enumerate(XRAY_FP_LIST, 1)}


def prompt_fingerprint(
    label: str = "",
    current: str = DEFAULT_FP,
) -> str:
    """
    Интерактивный выбор TLS Fingerprint.

    Параметры
    ---------
    label   : необязательный суффикс для заголовка (напр. "Exit Node #2").
    current : значение по умолчанию, если пользователь нажал Enter без ввода.

    Возвращает
    ----------
    str : валидное имя FP из XRAY_FP_LIST.

    Особенности
    -----------
    - Принимает как номер пункта, так и имя FP напрямую.
    - Если ввод пуст — возвращает `current` (fallback без шума).
    - При некорректном вводе предупреждает и повторяет запрос.
    - KeyboardInterrupt прокидывается наверх (для корректной отмены установки).
    """
    try:
        from vless_installer._core import (  # type: ignore[import]
            _box_top, _box_item, _box_bottom, _box_row,
            success, warn,
            CYAN, NC, BLUE,
        )
    except ImportError:
        # Fallback для юнит-тестов вне основного проекта
        def _box_top(s: str = "") -> None: print(f"┌─ {s}")
        def _box_item(k: str, v: str) -> None: print(f"│  [{k}] {v}")
        def _box_bottom() -> None: print("└" + "─" * 40)
        def _box_row(s: str = "") -> None: print(f"│  {s}")
        def success(s: str) -> None: print(f"[OK] {s}")
        def warn(s: str) -> None: print(f"[!] {s}")
        CYAN = NC = BLUE = ""

    title = f"Fingerprint браузера (TLS/uTLS){' — ' + label if label else ''}"
    _box_top(f"{BLUE}{title}{NC}")
    _box_row()
    for num, fp_name in _FP_MENU.items():
        _box_item(num, fp_name)
    _box_row()
    _box_bottom()

    valid_names = set(XRAY_FP_LIST)
    default_num = next(
        (k for k, v in _FP_MENU.items() if v == current),
        "1",
    )

    while True:
        try:
            raw = input(
                f"  {CYAN}Выбор [{default_num} = {current}]"
                f" (номер или имя, Enter = {current}): {NC}"
            ).strip()
        except KeyboardInterrupt:
            print()
            raise

        if not raw:
            success(f"  Fingerprint: {current}")
            return current

        if raw in _FP_MENU:
            chosen = _FP_MENU[raw]
            success(f"  Fingerprint: {chosen}")
            return chosen

        if raw in valid_names:
            success(f"  Fingerprint: {raw}")
            return raw

        warn(f"  Некорректный выбор. Введите номер 1–{len(XRAY_FP_LIST)} или имя из списка.")
