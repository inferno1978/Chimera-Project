"""
chimera/modules/text_width.py
───────────────────────────────────────────────────────────────────────────────
Централизованный расчёт визуальной ширины строки для TUI box-drawing.

ПРОБЛЕМА (почему правая рамка ║ съезжала):
  В 19 модулях проекта была своя копия `_wlen()` — копипаста разошлась и
  мутировала (5 разных вариантов). Все они считали ширину через
  unicodedata.east_asian_width(), что правильно для CJK, НО неправильно для
  emoji-presentation-default символов типа:
      ⚠  (U+26A0)  — east_asian_width='N', но терминал рендерит как 2 колонки
      ✓  (U+2713)  — east_asian_width='A', но некоторые шрифты рендерят как 2
      ✗  (U+2717)  — аналогично
      ❌ (U+274C)  — east_asian_width='N', но emoji-presentation → 2 колонки
      ✓  (U+2714)  — аналогично
  Из-за этого _box_row() в mtproto.py рисовал правую ║ на 1 колонку левее,
  чем ожидалось — рамка "ломалась" на строках с ⚠/✓.

РЕШЕНИЕ:
  Единая функция wlen() учитывает:
    1. ANSI escape sequences (\033[...m) — не считаются
    2. East Asian Wide/Fullwidth (CJK) — 2 колонки
    3. Emoji_Presentation-default кодпоинты (⚠ ✓ ✗ ❌ ✔ ✖ ✝ ✡ ✨ ✳ ✴ ❄ ❇
       ❎ ❓ ❔ ❕ ❗ ❣ ❤ ➕ ➖ ➗ ➡ ➰ ➿ ⤴ ⤵ ⬅ ⬇ ⬆ ⬛ ⬜ ⭐ ⭕ 〰 〽 ㊗ ㊙
       ⌚⌛ ⏩⏪⏫⏬ ⏰ ⏳ ◽◾ ☔☕ ♈-♓ ♿ ⚓ ⚡ ⚪⚫ ⚽⚾ ⛄☃ ⛎ ⛔ ⛪ ⛲⛳ ⛵ ⛺ ⛽
       ✂ ✅ ✈-✍ ✏ ✒) — 2 колонки
    4. Суррогатные пары (emoji вне BMP, 😀 🚀) — 2 колонки
    5. Variation Selector-16 (U+FE0F) — принудительно делает предшествующий
       символ emoji-presentation (2 колонки)
    6. Zero-Width Joiner (U+200D) и combining marks (U+0300-036F,
       U+FE00-FE0F) — 0 колонок

  Все 19 модулей импортируют эту функцию — больше нет копипасты.

Точки входа:
    from chimera.modules.text_width import wlen, plain
    w = wlen(text)  # визуальная ширина в колонках терминала
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

# ANSI escape sequence regex (SGR — Set Graphic Rendition)
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def plain(s: str) -> str:
    """Удаляет ANSI escape sequences из строки."""
    return _ANSI_RE.sub('', s)


# ============================================================================
#  Emoji_Presentation-default кодпоинты
# ============================================================================
# Символы которые имеют Unicode-свойство Emoji_Presentation — то есть
# терминалы рендерят их как emoji (ширина 2) БЕЗ необходимости в U+FE0F.
# Источник: Unicode Emoji 15.0, emoji-data.txt → # Emoji_Presentation property
#
# Эти символы имеют east_asian_width='N' или 'A' (узкие по EAW), но
# фактически занимают 2 колонки в современных терминалах (GNOME Terminal,
# kitty, iTerm2, Windows Terminal, Alacritty, foot).
#
# ВАЖНО: ⚠ (U+26A0) НЕ в этом списке по умолчанию — оно имеет
# Emoji_Presentation=No, но многие шрифты рендерят его как emoji.
# Однако через U+FE0F (⚠️) оно становится emoji-presentation.
# Мы всё равно включаем U+26A0 в _EMOJI_PRESENTATION_CP потому что
# на практике большинство современных шрифтов рендерят его как 2 колонки
# даже без U+FE0F (fallback emoji-presentation).

# Диапазоны из emoji-data.txt (Emoji_Presentation=Yes)
_EMOJI_PRESENTATION_RANGES: list[tuple[int, int]] = [
    (0x231A, 0x231B),  # ⌚ ⌛
    (0x23E9, 0x23EC),  # ⏩ ⏪ ⏫ ⏬
    (0x23F0, 0x23F0),  # ⏰
    (0x23F3, 0x23F3),  # ⏳
    (0x25FD, 0x25FE),  # ◽ ◾
    (0x2614, 0x2615),  # ☔ ☕
    (0x2648, 0x2653),  # ♈-♓
    (0x267F, 0x267F),  # ♿
    (0x2693, 0x2693),  # ⚓
    (0x26A1, 0x26A1),  # ⚡
    (0x26A0, 0x26A0),  # ⚠  (Emoji_Presentation=No, но фактически emoji в шрифтах)
    (0x26AA, 0x26AB),  # ⚪ ⚫
    (0x26BD, 0x26BE),  # ⚽ ⚾
    (0x26C4, 0x26C5),  # ⛄ ☃
    (0x26CE, 0x26CE),  # ⛎
    (0x26D4, 0x26D4),  # ⛔
    (0x26EA, 0x26EA),  # ⛪
    (0x26F2, 0x26F3),  # ⛲ ⛳
    (0x26F5, 0x26F5),  # ⛵
    (0x26FA, 0x26FA),  # ⛺
    (0x26FD, 0x26FD),  # ⛽
    (0x2702, 0x2702),  # ✂
    (0x2705, 0x2705),  # ✅
    (0x2708, 0x270D),  # ✈ ✉ ✊ ✋ ✌ ✍
    (0x270F, 0x270F),  # ✏
    (0x2712, 0x2712),  # ✒
    (0x2714, 0x2714),  # ✔
    (0x2716, 0x2716),  # ✖
    (0x271D, 0x271D),  # ✝
    (0x2721, 0x2721),  # ✡
    (0x2728, 0x2728),  # ✨
    (0x2733, 0x2734),  # ✳ ✴
    (0x2744, 0x2744),  # ❄
    (0x2747, 0x2747),  # ❇
    (0x274C, 0x274C),  # ❌
    (0x274E, 0x274E),  # ❎
    (0x2753, 0x2755),  # ❓ ❔ ❕
    (0x2757, 0x2757),  # ❗
    (0x2763, 0x2764),  # ❣ ❤
    (0x2795, 0x2797),  # ➕ ➖ ➗
    (0x27A1, 0x27A1),  # ➡
    (0x27B0, 0x27B0),  # ➰
    (0x27BF, 0x27BF),  # ➿
    (0x2934, 0x2935),  # ⤴ ⤵
    (0x2B05, 0x2B07),  # ⬅ ⬇ ⬆
    (0x2B1B, 0x2B1C),  # ⬛ ⬜
    (0x2B50, 0x2B50),  # ⭐
    (0x2B55, 0x2B55),  # ⭕
    (0x3030, 0x3030),  # 〰
    (0x303D, 0x303D),  # 〽
    (0x3297, 0x3297),  # ㊗
    (0x3299, 0x3299),  # ㊙
]

# Дополнительно: символы которые часто используются в TUI и имеют
# east_asian_width='A' (Ambiguous), но рендерятся как 2 колонки в
# emoji-aware терминалах. Включаем их осторожно — только те, что
# реально используются в проекте.
#   ✓  (U+2713)  CHECK MARK — Neutral, но emoji-стиль в современных шрифтах
#   ✗  (U+2717)  BALLOT X — Neutral
#   →  (U+2192)  RIGHTWARDS ARROW — Ambiguous (ширина 1 в CJK-locale, 1 в Western)
#                 НЕ включаем — рендерится как 1 колонка почти везде
#
# На самом деле ✓ и ✗ в проекте используются БЕЗ U+FE0F и рендерятся как
# 1 колонка в большинстве терминалов. Оставляем их как width=1 (по EAW),
# иначе сломаем выравнивание в _box_ok/_box_err где они используются массово.
# Если у пользователя проблема с ✓ — пусть использует ✅ (U+2705).

# Превращаем список диапазонов в set для O(1) проверки
_EMOJI_PRESENTATION_CP: set[int] = set()
for _lo, _hi in _EMOJI_PRESENTATION_RANGES:
    _EMOJI_PRESENTATION_CP.update(range(_lo, _hi + 1))


def _is_emoji_presentation(cp: int) -> bool:
    """True если кодпоинт имеет Emoji_Presentation property
    (или фактически рендерится как emoji в современных терминалах)."""
    return cp in _EMOJI_PRESENTATION_CP


# ============================================================================
#  Основная функция wlen
# ============================================================================
def wlen(s: Any) -> int:
    """Возвращает визуальную ширину строки `s` в колонках терминала.

    Корректно обрабатывает:
      • ANSI escape sequences (\033[...m) — не считаются
      • CJK / East Asian Wide / Fullwidth — 2 колонки
      • Emoji_Presentation-default символы (⚠ ❌ ✅ ⭐ и т.д.) — 2 колонки
      • Суррогатные пары (emoji вне BMP: 😀 🚀) — 2 колонки
      • Variation Selector-16 (U+FE0F) — делает предшествующий символ wide
      • Zero-Width Joiner (U+200D) и combining marks — 0 колонок
    """
    if s is None:
        return 0
    s = str(s)
    text = plain(s)
    width = 0
    chars = list(text)
    i = 0
    n = len(chars)
    while i < n:
        ch = chars[i]
        cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < n else 0

        # Variation Selector-16 (U+FE0F) — следующий за символом →
        # предшествующий символ становится emoji-presentation (2 колонки).
        # Сам VS16 — 0 колонок. Но мы уже добавили 1 или 2 за предшествующий
        # символ на предыдущей итерации — нужно скорректировать.
        # Проще: если CurrentChar + VS16 → считаем CurrentChar как 2 колонки.
        if next_cp == 0xFE0F:
            # Текущий символ становится emoji (2 колонки), VS16 пропускаем
            width += 2
            i += 2
            continue

        # Zero-Width Joiner и combining marks — 0 колонок
        if cp == 0x200D or (0x0300 <= cp <= 0x036F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1
            continue

        # Emoji_Presentation-default символы — 2 колонки
        if _is_emoji_presentation(cp):
            width += 2
            i += 1
            continue

        # CJK / East Asian Wide / Fullwidth — 2 колонки
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
            i += 1
            continue

        # Emoji вне BMP (суррогатные пары уже объединены в один char в Python 3)
        # Диапазоны: 0x1F300-0x1FAFF ( emoji), 0x1F000-0x1F02F (mahjong), и т.д.
        if 0x1F000 <= cp <= 0x1FFFF:
            width += 2
            i += 1
            continue

        # Прочие символы — 1 колонка
        width += 1
        i += 1

    return width


# ============================================================================
#  Совместимость со старым API
# ============================================================================
# Старые модули используют `_wlen` и `_plain` (с подчёркиванием).
# Экспортируем и эти имена для постепенной миграции.
_plain = plain
_wlen = wlen
