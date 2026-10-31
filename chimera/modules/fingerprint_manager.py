"""
fingerprint_manager.py
======================
Централизованное управление TLS Fingerprint (FP) для Xray/VLESS.

Отвечает за:
- Полный список FP, поддерживаемых Xray-core (LIVE-валидация, см. ниже).
- Интерактивный выбор FP пользователем (установка + генераторы fragment).
- Валидацию ввода и безопасный fallback.
- resolve_client_fp()/save_default_fingerprint() — эффективный FP
  для генераторов клиентских конфигов/ссылок (fragment-стек v4.31).

LIVE-валидация (31.10.2026, Xray-core 26.10.29, `xray run -test`):
  Ядро валидирует fingerprint ПРИ ПАРСИНГЕ конфига — строго:
    unknown "fingerprint": <имя> → «Failed to build REALITY/TLS config».
  Приняты ядром (rc=0): chrome, firefox, safari, ios, android, edge,
  360, qq, random, randomized, randomizednoalpn.
  Отвергнуты: none (в обеих секциях — reality И tls; в старом списке
  Химеры был латентным багом), все версионные имена вида chrome_120 /
  ios_17_0 / firefox_133 (utls-имена ядром НЕ принимаются).
  Пустой fingerprint/его отсутствие — валидны (ядро подставляет дефолт).

- REALITY-guard: random/randomized/randomizednoalpn несовместимы с REALITY
  (auth-proof передаётся в session_id ClientHello; randomized-Hello
  сервер не разбирает → соединение молча уходит на сайт-приманку).
  Подтверждено живым тестом на флоте проекта (v9-конфиг, 2026-09-05).

Интегрируется в _core.py минимально и точечно:
  - PARAM_FINGERPRINT хранит выбранный FP для текущей сессии установки.
  - prompt_fingerprint() вызывается из prompt_parameters() и ручного ввода нод.
  - resolve_client_fp() — из fragment-стека (link/config/presets/noise/mux)
    и client_config_export (v4.31: FP настраиваем везде, не прибит гвоздями).
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = [
    "XRAY_FP_LIST",
    "DEFAULT_FP",
    "REALITY_INCOMPATIBLE_FP",
    "XRAY_FP_SOURCE_NOTE",
    "reality_fp_warning",
    "prompt_fingerprint",
    "resolve_client_fp",
    "save_default_fingerprint",
    "STATE_FILE",
]

# ---------------------------------------------------------------------------
#  Полный список FP, поддерживаемых Xray-core 26.10.29 (utls).
#  Источник: LIVE-валидация `xray run -test` (parse-time strict) —
#  ядро отвергает неизвестные имена на этапе сборки конфига.
#  Порядок: популярные первыми для удобства выбора.
# ---------------------------------------------------------------------------
XRAY_FP_LIST: list[str] = [
    "chrome",           # Google Chrome (наиболее распространён)
    "firefox",          # Mozilla Firefox
    "safari",           # Apple Safari (desktop)
    "ios",              # Safari on iOS / iPadOS
    "android",          # Android / okhttp
    "edge",             # Microsoft Edge
    "360",              # 360 Browser (Qihoo)
    "qq",               # QQ Browser (Tencent)
    "random",           # случайный из реальных браузеров (выбирает Xray при старте)
    "randomized",       # рандомизированный при каждом хендшейке (uTLS randomized)
    "randomizednoalpn", # uTLS randomized без ALPN (live 26.10.29: принято ядром)
]

DEFAULT_FP: str = "chrome"

XRAY_FP_SOURCE_NOTE: str = (
    "LIVE-валидация 31.10.2026, Xray-core 26.10.29, `xray run -test`: "
    "ядро принимает 11 имён (список выше); `none` отвергается в обеих "
    "секциях (reality и tls) — удалён из списка (был латентным багом "
    "Химеры); `randomizednoalpn` добавлен. Версионные utls-имена "
    "(chrome_120, ios_17_0 и т.п.) ядром НЕ принимаются."
)

# ---------------------------------------------------------------------------
#  REALITY-guard (v9, 2026-09-05; расширено v4.31)
#  random/randomized/randomizednoalpn НЕ работают с REALITY-инбаундами:
#  REALITY несёт auth-proof (UUID-производную) в поле session_id
#  ClientHello; hello, порождаемый randomized-семейством, сервер разобрать
#  не может → решает «чужой» и молча форвардит соединение на сайт-приманку
#  (dest). Снаружи это выглядит как «TCP жив, туннеля нет».
#  Для plain-TLS (не REALITY) random работать может — поэтому из общего
#  списка FP не удаляем, а предупреждаем/отклоняем на этапе выбора.
# ---------------------------------------------------------------------------
REALITY_INCOMPATIBLE_FP: frozenset = frozenset({
    "random", "randomized", "randomizednoalpn",
})

# ── state.json (дефолт FP ноды; live-параметры установщика) ────────────────
STATE_FILE = Path("/var/lib/xray-installer/state.json")


def reality_fp_warning(fp: str) -> str:
    """Предупреждение для FP, несовместимых с REALITY ("" = совместим)."""
    if fp not in REALITY_INCOMPATIBLE_FP:
        return ""
    return (
        f"FP '{fp}' несовместим с REALITY: auth-proof передаётся в session_id "
        "ClientHello, а randomized-семейство (random/randomized/"
        "randomizednoalpn) порождает Hello, из которого сервер "
        "не может извлечь proof — соединение молча уходит на сайт-приманку "
        "(TCP жив, туннеля нет). Для REALITY используй фиксированный "
        "браузерный FP: chrome / firefox / safari / ios / android / "
        "edge / 360 / qq."
    )


def resolve_client_fp(state, override=None) -> str:
    """
    Эффективный FP для генерации клиентских артефактов (ссылки/JSON).

    Приоритет: override (выбор в меню генерации) → state.fingerprint
    (дефолт ноды) → DEFAULT_FP. Неверные/неподдерживаемые значения
    молча сходятся к валидным (генератор НЕ должен падать на мусорном
    state.json), см. LIVE-валидацию в шапке модуля.
    """
    allowed = set(XRAY_FP_LIST)
    cur = ""
    if isinstance(state, dict):
        cur = str(state.get("fingerprint", "") or "").strip().lower()
    ov = str(override or "").strip().lower()
    if ov in allowed:
        return ov
    if cur in allowed:
        return cur
    return DEFAULT_FP


def save_default_fingerprint(fp: str) -> bool:
    """
    Сохраняет FP как дефолт ноды (state.json → "fingerprint").

    Используется пунктами «сохранить как дефолт» в меню fragment-стека:
    новый FP применяют все последующие генерации (ссылки, JSON-конфиги,
    экспорт) без повторного выбора.
    """
    fp = str(fp or "").strip().lower()
    if fp not in set(XRAY_FP_LIST):
        return False
    st: dict = {}
    if STATE_FILE.exists():
        try:
            st = json.loads(STATE_FILE.read_text())
        except Exception:
            st = {}
        if not isinstance(st, dict):
            st = {}
    st["fingerprint"] = fp
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        return True
    except Exception:
        return False


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

        # REALITY-guard: randomized-семейство несовместимо с REALITY
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
