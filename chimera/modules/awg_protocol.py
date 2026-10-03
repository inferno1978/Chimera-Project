"""
chimera/modules/awg_protocol.py
───────────────────────────────────────────────────────────────────────────────
Версионирование протокола AmneziaWG (2.0 / 3.1) — единая точка правды.

AmneziaWG 3.1 (релиз 27-28.08.2026) расширяет обфускацию 2.0 transport-
protection-механизмами: шифрование заголовков (HeaderProtectionKey),
паддинг пакетов (ContentPaddingAddition), рандомизация таймеров
(RekeyAfterTime/RekeyTimeout/RejectAfterTime/KeepaliveTimeout/
MaxHandshakeAttempts), RandomTrailers и DisableCookies. Параметры 2.0
(Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5) остаются базой; 3.1 добавляет к ним
9 директив.

Этот модуль НЕ знает про state/конфиги/интерфейсы — только чистые функции
над параметрами. Его используют все три AWG-мира Chimera:
  • standalone (awg_standalone/awg_peers/awg_qr, AWGS_*)
  • каскад (awg_cascade, AWGS_*)
  • Mode B transport (awg_transport, AWG_* в _core.py)

Диапазоны генерации 3.1 соответствуют констрейнтам 3x-ui 3.8.5
GenerateObfuscation31 — тем же, что использует wpp_awg.py (мир WPP-профилей,
где AWG 3.1 уже поддерживается с v2.4.2). Это даёт консистентные отпечатки
обфускации между всеми подсистемами проекта.

Важные правила (выстраданные на 2.0, см. v5.4.5):
  • Пустые директивы в .conf пишутся как «# Key = » — голое «Key = »
    валит `awg setconf` на целом ряде сборок amneziawg-tools.
  • H1-H4 в 3.1 генерируются как одиночные int в НЕПЕРЕСЕКАЮЩИХСЯ бандах
    от 5 (значения 1-4 — узнаваемые vanilla-WireGuard типы сообщений;
    формат как в GenerateObfuscation31 / wpp_awg).
  • I1 в 3.1 — всегда CPS-тег «<r N>» (N 32-256), I2-I5 — пустые.
"""
from __future__ import annotations

import base64
import random
import re
from typing import Optional

# ── Версии протокола ─────────────────────────────────────────────────────────
AWG_VERSION_20: str = "2.0"
AWG_VERSION_31: str = "3.1"
AWG_VERSIONS: tuple = (AWG_VERSION_20, AWG_VERSION_31)

# ── Официальные форматы значений AWG 3.1 (amneziawg-tools/src/type.c) ─────────
# u32_range_from_string / u16_range_from_string принимают КАК одиночное
# число «N», так и диапазон «N-M» (hi >= lo). Это касается H1-H4 (u32) и
# ВСЕХ шести диапазонных директив 3.1 (u16): ContentPaddingAddition,
# RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout,
# MaxHandshakeAttempts.
# RandomTrailers / DisableCookies — parse_bool: «on»/«off» (без учёта
# регистра) или «0»/«1» (цифры; parse_bool трактует любое ненулевое число
# как true). Генерация по-прежнему пишет «on» и диапазоны «N-M» — это
# канонический вид; валидатор принимает весь официальный синтаксис, чтобы
# конфиги из внешних генераторов (ARCHITECT, 3x-ui, вручную по wiki)
# импортировались без правок.
_RANGE_OR_SINGLE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def awg_normalize_version(version) -> str:
    """Нормализует обозначение версии протокола к "2.0" | "3.1".

    Принимает толерантно: "2.0"/"2"/"20"/"awg20"/"3.1"/"3"/"31"/"awg31"/
    "awg31" (wpp-имя) и т.п. Всё нераспознанное (в т.ч. не-строки —
    MagicMock из тестов, None) безопасно нормализуется к "2.0":
    существующие установки/state без поля версии = 2.0.
    """
    if not isinstance(version, str):
        return AWG_VERSION_20
    v = version.strip().lower()
    # Порядок важен: «amneziawg» содержит «awg», «awg» содержит «wg» —
    # вырезаем от длинного к короткому.
    for prefix in ("amneziawg", "amnezia", "awg", "wg"):
        v = v.replace(prefix, "")
    v = v.replace(" ", "").replace("_", "").replace("-", "")
    if v in ("3.1", "3", "31", "3,1"):
        return AWG_VERSION_31
    return AWG_VERSION_20


def awg_is_31(version) -> bool:
    """True если версия — AmneziaWG 3.1 (после нормализации)."""
    return awg_normalize_version(version) == AWG_VERSION_31


def awg_protocol_label(version) -> str:
    """Человекочитаемый лейбл: "AmneziaWG 2.0" | "AmneziaWG 3.1"."""
    return "AmneziaWG 3.1" if awg_is_31(version) else "AmneziaWG 2.0"


def awg_vpn_uri_protocol_version(version) -> str:
    """protocol_version для vpn:// URI (формат импорта Amnezia Client).

    2.0 → "2" (историческое значение, захардкоженное до v5.5),
    3.1 → "3" (мажор протокола; AmneziaVPN 5.0.1.5+ ожидает новое
    значение для 3.1-профилей).
    """
    return "3" if awg_is_31(version) else "2"


# ── Дополнительные параметры AWG 3.1 ─────────────────────────────────────────
# snake_case ключи в state/params  →  CamelCase директивы .conf.
# Порядок рендера — как в GenerateObfuscation31 / wpp_awg._parameter_lines:
# сразу после I1-I5.
AWG31_EXTRA_KEYS: tuple = (
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
)

AWG31_DIRECTIVE_NAMES: dict = {
    "header_protection_key":  "HeaderProtectionKey",
    "content_padding_addition": "ContentPaddingAddition",
    "rekey_after_time":       "RekeyAfterTime",
    "rekey_timeout":          "RekeyTimeout",
    "reject_after_time":      "RejectAfterTime",
    "keepalive_timeout":      "KeepaliveTimeout",
    "max_handshake_attempts": "MaxHandshakeAttempts",
    "random_trailers":        "RandomTrailers",
    "disable_cookies":        "DisableCookies",
}

# Флаговые параметры 3.1 — допустимое значение только "on" (как в
# GenerateObfuscation31; «off» не генерируем: фичи дают саму защиту 3.1).
AWG31_FLAG_KEYS: tuple = ("random_trailers", "disable_cookies")

# Диапазонные параметры 3.1 — строка "N-M". (lo, hi) — допустимые границы
# обеих компонент (констрейнты GenerateObfuscation31 / wpp_awg).
AWG31_RANGE_KEYS: dict = {
    "content_padding_addition": (0, 64),       # cp_low 8-24 + 8..40
    "rekey_after_time":         (100, 200),    # rekey 100-120 + 10..40
    "rekey_timeout":            (3, 10),       # timeout 3-6 + 1..4
    "reject_after_time":        (130, 300),    # reject >= rekey_high + 30..60
    "keepalive_timeout":        (8, 20),       # keepalive 8-12 + 2..8
    "max_handshake_attempts":   (15, 50),      # attempts 15-25 + 5..25
}

_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


def awg31_generate_header_protection_key() -> str:
    """Генерирует HeaderProtectionKey — base64 32 случайных байт (44 символа).

    Тот же формат, что `awg genkey` / `wg genkey` (Curve25519-ключи —
    тоже base64 32 байт), но без зависимости от бинарника: presets-слой
    обязан работать в unit-тестах без subprocess. os.urandom даёт
    криптографически стойкие 32 байта.
    """
    import os
    return base64.b64encode(os.urandom(32)).decode("ascii")


def awg31_generate_extra_params(rng: Optional[random.Random] = None) -> dict:
    """Генерирует 9 дополнительных параметров AWG 3.1.

    Диапазоны — констрейнты GenerateObfuscation31 (3x-ui 3.8.5),
    идентичны wpp_awg._parameters("awg31") — единый отпечаток генерации
    по всему проекту:
      HeaderProtectionKey      — 44-символьный base64 ключ
      ContentPaddingAddition   — "8-24 .. +8-40"
      RekeyAfterTime           — "100-120 .. +10-40"
      RekeyTimeout             — "3-6 .. +1-4"
      RejectAfterTime          — rekey_high + 30-60 .. +30-90
      KeepaliveTimeout         — "8-12 .. +2-8"
      MaxHandshakeAttempts     — "15-25 .. +5-25"
      RandomTrailers           — "on"
      DisableCookies           — "on"
    """
    r = rng or random

    cp_low = r.randint(8, 24)
    rekey_low = r.randint(100, 120)
    rekey_high = rekey_low + r.randint(10, 40)
    reject_low = rekey_high + r.randint(30, 60)
    timeout_low = r.randint(3, 6)
    keepalive_low = r.randint(8, 12)
    attempts_low = r.randint(15, 25)

    return {
        "header_protection_key": awg31_generate_header_protection_key(),
        "content_padding_addition": "%d-%d" % (cp_low, cp_low + r.randint(8, 40)),
        "rekey_after_time": "%d-%d" % (rekey_low, rekey_high),
        "rekey_timeout": "%d-%d" % (timeout_low, timeout_low + r.randint(1, 4)),
        "reject_after_time": "%d-%d" % (reject_low, reject_low + r.randint(30, 90)),
        "keepalive_timeout": "%d-%d" % (keepalive_low, keepalive_low + r.randint(2, 8)),
        "max_handshake_attempts": "%d-%d" % (attempts_low, attempts_low + r.randint(5, 25)),
        "random_trailers": "on",
        "disable_cookies": "on",
    }


def awg31_validate_extra_params(params: dict) -> tuple:
    """Валидирует 9 дополнительных параметров AWG 3.1.

    Возвращает (ok, error_message). Правила (официальный синтаксис
    amneziawg-tools/src/config.c + type.c, сверено с amneziawg-go uapi.go):
      • HeaderProtectionKey — непустая строка 43-44 символа base64 (32 байта;
        парсится тем же parse_key, что и PrivateKey);
      • диапазонные параметры — «N» ИЛИ «N-M» (обе формы официальные),
        обе компоненты в допустимых границах, N <= M;
      • флаговые (RandomTrailers/DisableCookies) — «on»/«off»/«0»/«1»
        (parse_bool amneziawg-tools; генерация пишет «on»);
      • кросс-проверки таймеров (ARCHITECT, «сессия должна прожить дольше
        окна keepalive+rekey»): RejectAfterTime.lo > KeepaliveTimeout.hi +
        RekeyTimeout.hi и RekeyAfterTime.hi < RejectAfterTime.lo.
    """
    if not isinstance(params, dict):
        return False, "params должен быть dict"

    hpk = params.get("header_protection_key", "")
    if not isinstance(hpk, str) or not (43 <= len(hpk) <= 44):
        return False, ("HeaderProtectionKey должен быть base64-строкой "
                       "43-44 символа (32 байта)")
    try:
        decoded = base64.b64decode(hpk, validate=True)
        if len(decoded) < 30:
            return False, "HeaderProtectionKey: некорректный base64"
    except Exception:
        return False, "HeaderProtectionKey: не является валидным base64"

    # Диапазонные параметры: официально «N» или «N-M» (type.c)
    parsed_ranges: dict = {}
    for key, (lo, hi) in AWG31_RANGE_KEYS.items():
        v = params.get(key, "")
        if isinstance(v, int):
            v = str(v)
        if not isinstance(v, str):
            return False, f"{AWG31_DIRECTIVE_NAMES[key]} должен быть числом или строкой 'N'/'N-M'"
        m = _RANGE_OR_SINGLE_RE.match(v.strip())
        if not m:
            return False, (f"{AWG31_DIRECTIVE_NAMES[key]}='{v}' не в формате "
                           f"'N' или 'N-M'")
        n = int(m.group(1))
        m_hi = int(m.group(2)) if m.group(2) is not None else n
        if not (lo <= n <= hi and lo <= m_hi <= hi):
            return False, (f"{AWG31_DIRECTIVE_NAMES[key]}='{v}' вне диапазона "
                           f"({lo}-{hi})")
        if n > m_hi:
            return False, (f"{AWG31_DIRECTIVE_NAMES[key]}='{v}': N > M")
        parsed_ranges[key] = (n, m_hi)

    # Флаговые параметры: parse_bool — «on»/«off»/«0»/«1» (регистронезависимо)
    for key in AWG31_FLAG_KEYS:
        v = params.get(key, "")
        if isinstance(v, int):
            v = str(v)
        if not isinstance(v, str) or v.strip().lower() not in (
                "on", "off", "0", "1"):
            return False, (f"{AWG31_DIRECTIVE_NAMES[key]} должен быть "
                           f"'on'/'off'/'0'/'1' (фактически: {v!r})")

    # Кросс-валидация таймеров (сверка с генератором ARCHITECT —
    # «RejectAfterTime должен быть больше KeepaliveTimeout + RekeyTimeout,
    # иначе сессия умрёт раньше, чем успеет обновиться» и
    # «RekeyAfterTime < RejectAfterTime»).
    if all(k in parsed_ranges for k in ("reject_after_time",
                                        "keepalive_timeout",
                                        "rekey_timeout")):
        rej_lo = parsed_ranges["reject_after_time"][0]
        keep_hi = parsed_ranges["keepalive_timeout"][1]
        rkey_hi = parsed_ranges["rekey_timeout"][1]
        if rej_lo <= keep_hi + rkey_hi:
            return False, (f"RejectAfterTime (от {rej_lo}с) должен быть больше "
                           f"KeepaliveTimeout + RekeyTimeout "
                           f"({keep_hi}+{rkey_hi}={keep_hi + rkey_hi}с), иначе "
                           f"сессия умрёт раньше, чем успеет обновиться")
    if all(k in parsed_ranges for k in ("rekey_after_time", "reject_after_time")):
        rekey_hi = parsed_ranges["rekey_after_time"][1]
        rej_lo = parsed_ranges["reject_after_time"][0]
        if rekey_hi >= rej_lo:
            return False, (f"RekeyAfterTime (до {rekey_hi}с) должен быть меньше "
                           f"RejectAfterTime (от {rej_lo}с)")

    return True, ""


def awg_render_31_lines(params: dict) -> str:
    """Рендерит 9 директив AWG 3.1 для .conf (сразу после I1-I5).

    Единое правило проекта (v5.4.5): непустые — «Key = value», пустые —
    «# Key = » (голое «Key = » валит awg setconf на ряде сборок).
    Параметры 2.0-набора (Jc…I5) сюда НЕ входят — их рендерят
    существующие генераторы, этот модуль только дополняет их блоком 3.1.

    Пустой params / отсутствие ключей → все строки закомментированы
    (ситуация «3.1-конфиг без 3.1-параметров» — валидный fallback,
    деградирует до 2.0-обфускации, но парсится любыми инструментами).
    """
    params = params if isinstance(params, dict) else {}
    lines = []
    for key in AWG31_EXTRA_KEYS:
        directive = AWG31_DIRECTIVE_NAMES[key]
        val = params.get(key, "")
        if val:
            lines.append(f"{directive} = {val}")
        else:
            lines.append(f"# {directive} = ")
    return "\n".join(lines)


def awg31_merge_into_params(base_20_params: dict,
                            extra_31: Optional[dict] = None) -> dict:
    """Собирает полный 3.1-набор: 16 базовых ключей 2.0 + 9 ключей 3.1.

    extra_31 — ЧАСТИЧНЫЙ или полный набор 3.1-параметров (явные значения
    пользователя/overrides). Недостающие ключи догенерируются автоматически
    (awg31_generate_extra_params), затем явные значения накладываются сверху.
    base_20_params не мутируется.
    """
    merged = dict(base_20_params or {})
    # Полный сгенерированный набор — база; ЧАСТИЧНЫЙ extra_31 (явные
    # overrides пользователя) накладывается сверху. Раньше частичный
    # extra_31 оставлял отсутствующие ключи пустыми.
    generated = awg31_generate_extra_params()
    if extra_31:
        for key, val in extra_31.items():
            if key in AWG31_EXTRA_KEYS and val:
                generated[key] = val
    for key in AWG31_EXTRA_KEYS:
        if key not in merged or not merged[key]:
            merged[key] = generated.get(key, "")
    return merged


def awg_state_protocol_version(state: Optional[dict]) -> str:
    """Читает protocol_version из state-словаря (standalone/каскад).

    Отсутствие ключа = старая установка = "2.0" (миграция без миграции).
    """
    if not isinstance(state, dict):
        return AWG_VERSION_20
    return awg_normalize_version(state.get("protocol_version", AWG_VERSION_20))
