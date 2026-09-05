"""
fingerprint_manager.py
======================
Централизованное управление TLS Fingerprint (FP) для Xray/VLESS.

Отвечает за:
- Полный актуальный список FP, поддерживаемых Xray-core.
- Интерактивный выбор FP пользователем во время установки.
- Валидацию ввода и безопасный fallback.
- REALITY-guard: random/randomized несовместимы с REALITY
  (auth-proof передаётся в session_id ClientHello; randomized-Hello
  сервер не разбирает → соединение молча уходит на сайт-приманку).
  Подтверждено живым тестом на флоте проекта (v9-конфиг, 2026-09-05).

Интегрируется в _core.py минимально и точечно:
  - PARAM_FINGERPRINT хранит выбранный FP для текущей сессии установки.
  - prompt_fingerprint() вызывается из prompt_parameters() и ручного ввода нод.
"""

from __future__ import annotations

__all__ = [
    "XRAY_FP_LIST",
    "DEFAULT_FP",
    "REALITY_INCOMPATIBLE_FP",
    "reality_fp_warning",
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

# ---------------------------------------------------------------------------
#  REALITY-guard (v9, 2026-09-05)
#  random/randomized НЕ работают с REALITY-инбаундами: REALITY несёт
#  auth-proof (UUID-производную) в поле session_id ClientHello; hello,
#  порождаемый random/randomized, сервер разобрать не может → решает
#  «чужой» и молча форвардит соединение на сайт-приманку (dest). Снаружи
#  это выглядит как «TCP жив, туннеля нет, соединение не устанавливается».
#  Для plain-TLS (не REALITY) random работать может — поэтому из общего
#  списка FP не удаляем, а предупреждаем/отклоняем на этапе выбора.
# ---------------------------------------------------------------------------
REALITY_INCOMPATIBLE_FP: frozenset = frozenset({"random", "randomized"})


def reality_fp_warning(fp: str) -> str:
    """Предупреждение для FP, несовместимых с REALITY ("" = совместим)."""
    if fp not in REALITY_INCOMPATIBLE_FP:
        return ""
    return (
        f"FP '{fp}' несовместим с REALITY: auth-proof передаётся в session_id "
        "ClientHello, а random/randomized порождает Hello, из которого сервер "
        "не может извлечь proof — соединение молча уходит на сайт-приманку "
        "(TCP жив, туннеля нет). Для REALITY используй фиксированный браузерный "
        "FP: chrome / firefox / safari / ios / android / edge / 360 / qq."
    )

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
        from chimera._core import (  # type: ignore[import]
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
        elif raw in valid_names:
            chosen = raw
        else:
            warn(f"  Некорректный выбор. Введите номер 1–{len(XRAY_FP_LIST)} или имя из списка.")
            continue

        # REALITY-guard: random/randomized несовместимы с REALITY
        w = reality_fp_warning(chosen)
        if w:
            warn(f"  {w}")
            try:
                confirm = input(
                    f"  {CYAN}Всё равно продолжить с '{chosen}'? [y/N]: {NC}"
                ).strip().lower()
            except KeyboardInterrupt:
                print()
                raise
            if confirm not in ("y", "yes", "д", "да"):
                print(f"  Выбор '{chosen}' отменён — выберите фиксированный браузерный FP.")
                continue

        success(f"  Fingerprint: {chosen}")
        return chosen
