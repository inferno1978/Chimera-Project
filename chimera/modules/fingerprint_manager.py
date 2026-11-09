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

v26.11.9 / форк uTLS от XTLS (09.11.2026):
  Xray-core v26.11.9 перешёл на собственный форк uTLS и добавил
  hellochrome_155 — имитацию актуального Chrome 155. По имеющимся данным
  RPRX, ТСПУ этот отпечаток пока не детектит — старый дефолт chrome
  (имитация Chrome 133 с X25519MLKEM768) уже научились отличать.
  Имя парсится ТОЛЬКО ядрами ≥ 26.11.9, поэтому это «клиентский-only» FP:
  допускается в артефактах Xray-семьи (vless-ссылки, Xray JSON,
  fragment-конфиги), но НЕ пишется в серверные outbounds каскада и в
  sing-box/mihomo-экспорты (свои uTLS, форковых имён не знают).
  См. FP_CLIENT_ONLY / FP_MIN_CORE_VERSION ниже.

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
    "FP_MIN_CORE_VERSION",
    "FP_CLIENT_ONLY",
    "FP_MENU_MARKER",
    "reality_fp_warning",
    "fp_client_only_note",
    "prompt_fingerprint",
    "resolve_client_fp",
    "save_default_fingerprint",
    "STATE_FILE",
]

# ---------------------------------------------------------------------------
#  Полный список FP, поддерживаемых Xray-core.
#  Источник: LIVE-валидация `xray run -test` (parse-time strict) —
#  ядро отвергает неизвестные имена на этапе сборки конфига.
#  Порядок: популярные первыми для удобства выбора; hellochrome_155 —
#  строго ПОСЛЕДНИМ: нумерация 1–11 прежняя (мышечная память юзера,
#  доки и скринкасты не ломаются).
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
    "hellochrome_155",  # Chrome 155, форк uTLS от XTLS — ядро ≥ 26.11.9 (см. ниже)
]

DEFAULT_FP: str = "chrome"

XRAY_FP_SOURCE_NOTE: str = (
    "LIVE-валидация 31.10.2026, Xray-core 26.10.29, `xray run -test`: "
    "ядро принимает 11 имён; `none` отвергается в обеих секциях "
    "(reality и tls) — удалён из списка (был латентным багом Химеры); "
    "`randomizednoalpn` добавлен. Версионные utls-имена классического "
    "апстрима (chrome_120, ios_17_0 и т.п.) ядром НЕ принимаются. "
    "09.11.2026, Xray-core v26.11.9 (собственный форк uTLS у XTLS): "
    "добавлен hellochrome_155 — парсится ТОЛЬКО ядрами ≥ 26.11.9,"
    "см. FP_CLIENT_ONLY."
)

# ---------------------------------------------------------------------------
#  FP из форка XTLS uTLS (ядро ≥ 26.11.9) — «клиентские-only» (09.11.2026)
#
#  hellochrome_155 появился в Xray-core v26.11.9: XTLS завели собственный
#  форк uTLS, чтобы быстро катить свежие отпечатки в ответ на ТСПУ.
#  По имеющимся данным RPRX, ТСПУ его пока не детектит — в отличие от
#  старого chrome (Chrome 133 + X25519MLKEM768), который уже отличают.
#
#  Ограничение: имя парсится ТОЛЬКО ядрами ≥ 26.11.9. Всё, что собирается
#  под чужие/старые ядра, его не примет:
#    • серверные outbounds каскада (entry→exit парсит ЯДРО СЕРВЕРА);
#    • sing-box / mihomo-экспорты (свои uTLS, форковых имён не знают);
#    • клиенты со старым Xray-core (unknown fingerprint → профиль не стартует).
#  Поэтому такие FP допускаются ТОЛЬКО в клиентских артефактах
#  Xray-семьи (vless-ссылки, Xray JSON, fragment-конфиги) — и всегда с
#  примечанием (FP_MENU_MARKER / fp_client_only_note).
#  Когда флот серверов перейдёт на ядра ≥ 26.11.9 — множество можно
#  опустошить, и FP станет доступен везде.
# ---------------------------------------------------------------------------
FP_MIN_CORE_VERSION: dict[str, str] = {
    # имя FP → минимальная версия Xray-core, которая его парсит
    "hellochrome_155": "26.11.9",
}

FP_CLIENT_ONLY: frozenset = frozenset({
    "hellochrome_155",   # XTLS utls-fork: только клиентские артефакты Xray-семьи
})

# Короткая пометка «напротив» пункта меню (без ANSI — цвет добавляет caller).
# Длинное пояснение — fp_client_only_note(); требование к версии ядра —
# FP_MIN_CORE_VERSION.
FP_MENU_MARKER: dict[str, str] = {
    "hellochrome_155": (
        "НОВЫЙ (Chrome 155) — ТСПУ пока не видит; "
        "нужен клиент с Xray-core ≥ 26.11.9"
    ),
}

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


def fp_client_only_note(fp: str) -> str:
    """Полное пояснение для FP из FP_CLIENT_ONLY ("" = обычный FP).

    Требование к ядру клиента, кто не примет, кому что оставить.
    Используется: предупреждение после выбора в prompt_fingerprint(),
    гард в user_fp_manager.apply_fp(), пометки в генераторах.
    Короткая версия для пунктов меню — FP_MENU_MARKER.
    """
    if fp not in FP_CLIENT_ONLY:
        return ""
    mv = FP_MIN_CORE_VERSION.get(fp, "26.11.9")
    return (
        f"FP '{fp}' — имитация свежего Chrome 155 (появился в Xray-core "
        f"v{mv} от 09.11.2026, форк uTLS у XTLS). По имеющимся данным, "
        "ТСПУ его пока не распознаёт — старый chrome (Chrome 133) уже "
        "научились отличать. ВАЖНО: имя парсится только ядрами v" + mv + "+, "
        "ссылки/конфиги с ним запустятся лишь в свежих сборках Xray-клиентов "
        "(Rawline / v2rayN / Karing с ядром ≥ v" + mv + "). Старые клиенты и "
        "mihomo-семья (Clash Verge / FlClash / роутеры) его не примут — "
        "им оставляйте fp=chrome. Конфиги Химеры с фрагментацией прикрывают "
        "ClientHello независимо от отпечатка — если сомневаетесь, берите chrome."
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
    server_side: bool = False,
) -> str:
    """
    Интерактивный выбор TLS Fingerprint.

    Параметры
    ---------
    label   : необязательный суффикс для заголовка (напр. "Exit Node #2").
    current : значение по умолчанию, если пользователь нажал Enter без ввода.
    server_side : True — контекст, где выбранный FP попадает в конфиг,
        парсимый ЯДРОМ СЕРВЕРА (outbound каскада entry→exit). FP из
        FP_CLIENT_ONLY (форк-имена, ядро ≥ 26.11.9) скрываются из меню
        и отклоняются при вводе именем — серверный флот на старых ядрах.

    Возвращает
    ----------
    str : валидное имя FP из XRAY_FP_LIST (при server_side — без FP_CLIENT_ONLY).

    Особенности
    -----------
    - Принимает как номер пункта, так и имя FP напрямую.
    - Если ввод пуст — возвращает `current` (fallback без шума).
    - При некорректном вводе предупреждает и повторяет запрос.
    - KeyboardInterrupt прокидывается наверх (для корректной отмены установки).
    - FP из FP_CLIENT_ONLY помечаются примечанием прямо в меню; после
      выбора показывается полное пояснение (fp_client_only_note).
    """
    try:
        from chimera._core import (  # type: ignore[import]
            _box_top, _box_item, _box_bottom, _box_row,
            success, warn,
            CYAN, NC, BLUE, DIM, YELLOW,
        )
    except ImportError:
        # Fallback для юнит-тестов вне основного проекта
        def _box_top(s: str = "") -> None: print(f"┌─ {s}")
        def _box_item(k: str, v: str) -> None: print(f"│  [{k}] {v}")
        def _box_bottom() -> None: print("└" + "─" * 40)
        def _box_row(s: str = "") -> None: print(f"│  {s}")
        def success(s: str) -> None: print(f"[OK] {s}")
        def warn(s: str) -> None: print(f"[!] {s}")
        CYAN = NC = BLUE = DIM = YELLOW = ""

    # server_side: форк-имена не предлагаются (конфиг парсит ядро сервера)
    menu_list = [fp for fp in XRAY_FP_LIST
                 if not (server_side and fp in FP_CLIENT_ONLY)]
    menu: dict[str, str] = {str(i): fp for i, fp in enumerate(menu_list, 1)}
    valid_names = set(menu_list)

    title = f"Fingerprint браузера (TLS/uTLS){' — ' + label if label else ''}"
    _box_top(f"{BLUE}{title}{NC}")
    _box_row()
    for num, fp_name in menu.items():
        note = ""
        if (not server_side) and fp_name in FP_MENU_MARKER:
            note = f"  {DIM}— {FP_MENU_MARKER[fp_name]}{NC}"
        _box_item(num, f"{fp_name}{note}")
    # Примечание-требование под списком (одно на каждый client-only FP)
    if not server_side:
        for fp_name in menu_list:
            if fp_name in FP_CLIENT_ONLY:
                _box_row()
                _box_row(f"  {YELLOW}⚠ {fp_name}{NC} — запустится только в "
                         f"клиентах с ядром Xray ≥ "
                         f"{FP_MIN_CORE_VERSION.get(fp_name, '?')} "
                         f"(свежие Rawline / v2rayN);")
                _box_row(f"    старым клиентам и mihomo-семье — {DEFAULT_FP}")
    _box_row()
    _box_bottom()

    default_num = next(
        (k for k, v in menu.items() if v == current),
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

        if raw in menu:
            chosen = menu[raw]
        elif raw in valid_names:
            chosen = raw
        elif server_side and raw in FP_CLIENT_ONLY:
            # Ввели именем форк-FP в серверном контексте — объясняем,
            # а не отшиваем «некорректным выбором».
            warn(f"  FP '{raw}' — только для клиентских ссылок: серверное ядро "
                 f"поймёт его лишь с Xray-core "
                 f"v{FP_MIN_CORE_VERSION.get(raw, '?')}. "
                 "Для серверной стороны выберите другой FP.")
            continue
        else:
            warn(f"  Некорректный выбор. Введите номер 1–{len(menu_list)} или имя из списка.")
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

        # Форк-FP (ядро ≥ 26.11.9): показываем требования ПОСЛЕ выбора —
        # юзер уже решил, но должен увидеть, кому ссылка не запустится.
        # Это инфо-блок, не подтверждение: меню выше уже предупреждало.
        if chosen in FP_CLIENT_ONLY:
            w2 = fp_client_only_note(chosen)
            if w2:
                warn(f"  {w2}")

        success(f"  Fingerprint: {chosen}")
        return chosen
