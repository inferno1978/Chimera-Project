"""
chimera/modules/awg_presets.py
───────────────────────────────────────────────────────────────────────────────
Carrier-пресеты для AmneziaWG 2.0.

Перенесено из bivlked/amneziawg-installer (awg_common.sh, manage_amneziawg.sh).
Реальные данные по операторам из issues/discussions bivlked.

Каждый пресет — это dict с параметрами:
  jc_min, jc_max   — диапазон Jc (junk packet count)
  jmin_min, jmin_max — диапазон Jmin
  jmax_delta_min, jmax_delta_max — приращение к Jmin для получения Jmax
  i1_mode           — "random" | "absent" | "binary" | "quic_mimicry"
                     (см. bivlked и docs.amnezia.org/CPS-формат)
                     random: случайный I1 в CPS-формате <r N>
                     absent: не указывать I1
                     binary: I1 как статичные байты в CPS-формате <b 0x...>
                     quic_mimicry: I1 как QUIC Initial packet (<b 0x...><r N><t>)

I1-I5 в AWG 2.0 — это НЕ голая hex-строка, а мини-язык тегов (CPS — Custom
Protocol Signature), задокументированный в docs.amnezia.org и в спецификации
amneziawg-go:
  <b 0x[hex]>  — статичные байты как есть (hex-encoded, всегда чётное число символов)
  <r [size]>   — [size] случайных байт
  <rd [size]>  — [size] случайных байт из [0-9]
  <rc [size]>  — [size] случайных байт из [a-zA-Z]
  <t>          — 4-байтный текущий unix-timestamp

Пакеты отправляются в порядке I1→I2→I3→I4→I5 перед каждым хендшейком; если I1
не задан — I2-I5 пропускаются тоже (I1 — обязательный якорь для остальных).
"""
from __future__ import annotations

import random
import re
from typing import Optional

from .awg_protocol import (
    awg_is_31, awg_normalize_version, awg31_generate_extra_params,
    awg31_validate_extra_params, awg31_merge_into_params, AWG_VERSION_20,
)


# ── Carrier-пресеты (из bivlked awg_common.sh) ──────────────────────────────
# Формат: (jc_min, jc_max, jmin_min, jmin_max, jmax_delta_min, jmax_delta_max, i1_mode)
# Соответствует _diagnose_carrier_known() в manage_amneziawg.sh
AWGS_CARRIER_PRESETS: dict = {
    "default": {
        "label":          "Default (проводной интернет)",
        "jc_min":         3,
        "jc_max":         6,
        "jmin_min":       40,
        "jmin_max":       89,
        "jmax_delta_min": 50,
        "jmax_delta_max": 250,
        "i1_mode":        "random",
        "description":    "Универсальный пресет для проводного интернета. "
                          "Jc 3-6 — компромисс между обфускацией и совместимостью.",
    },
    "mobile": {
        "label":          "Mobile (универсальный для мобильных DPI)",
        "jc_min":         3,
        "jc_max":         3,   # фиксированный Jc=3 — alkorrnd (Tele2) показал: Jc=3 >95% успеха
        "jmin_min":       30,
        "jmin_max":       50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,  # узкий Jmax — markmokrenko (Yota): Jmax=70 OK, Jmax>300 блокируется
        "i1_mode":        "random",
        "description":    "Jc=3 фиксированный, узкий Jmax. Для мобильных операторов "
                          "с DPI-блокировками (ТСПУ, Иран и т.п.).",
    },
    "beeline_msk": {
        "label":          "Билайн Москва",
        "jc_min":         3,
        "jc_max":         6,
        "jmin_min":       40,
        "jmin_max":       89,
        "jmax_delta_min": 50,
        "jmax_delta_max": 250,
        "i1_mode":        "random",
        "description":    "Билайн Москва — работает default preset, специальных "
                          "тweak'ов не требуется.",
    },
    "yota_msk": {
        "label":          "Yota Москва",
        "jc_min":         3,
        "jc_max":         3,
        "jmin_min":       30,
        "jmin_max":       50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,
        "i1_mode":        "random",
        "description":    "Yota Москва. Узкий Jmax обязателен — markmokrenko "
                          "зафиксировал блокировку при Jmax>300.",
    },
    "tele2_msk": {
        "label":          "Tele2 Москва",
        "jc_min":         3,
        "jc_max":         3,
        "jmin_min":       30,
        "jmin_max":       50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,
        "i1_mode":        "random",
        "description":    "Tele2 Москва. Jc=3 обязателен — alkorrnd "
                          "показал: Jc=3 >95% успеха, Jc=4 ~30%, Jc=5 <5%.",
    },
    "tele2_krasnoyarsk": {
        "label":          "Tele2 Красноярск",
        "jc_min":         3,
        "jc_max":         3,
        "jmin_min":       30,
        "jmin_max":       50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,
        "i1_mode":        "absent",   # без I1 (майская волна 2026)
        "description":    "Tele2 Красноярск. В майскую волну 2026 заработал "
                          "только с I1 отсутствующим (раньше требовался I1=<r 48>).",
    },
    "tattelecom": {
        "label":          "Таттелеком / Летай (Татарстан)",
        "jc_min":         3,
        "jc_max":         3,
        "jmin_min":       30,
        "jmin_max":       50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,
        "i1_mode":        "random",
        "description":    "Таттелеком / Летай (Татарстан). Mobile preset подходит.",
    },
    "megafon_regions": {
        "label":          "Мегафон (регионы)",
        "jc_min":         3,
        "jc_max":         3,
        "jmin_min":       30,
        "jmin_max":       50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,
        "i1_mode":        "absent",   # без I1
        "description":    "Мегафон регионы. Удалить параметр I1 — иначе блокировка.",
    },
    "tmobile_us": {
        "label":          "T-Mobile US",
        "jc_min":         6,
        "jc_max":         6,
        "jmin_min":       10,
        "jmin_max":       10,
        "jmax_delta_min": 40,
        "jmax_delta_max": 40,
        "i1_mode":        "binary",
        "description":    "T-Mobile US. Jc=6, узкие Jmin/Jmax, I1 как binary blob.",
    },
}


# ── Генерация параметров по пресету ─────────────────────────────────────────

def awgs_presets_list() -> list:
    """Возвращает список имён доступных пресетов."""
    return list(AWGS_CARRIER_PRESETS.keys())


def awgs_presets_get(name: str) -> Optional[dict]:
    """Возвращает пресет по имени или None."""
    return AWGS_CARRIER_PRESETS.get(name)


def awgs_presets_generate(name: str = "default", protocol_version: str = AWG_VERSION_20) -> dict:
    """
    Генерирует конкретные значения параметров обфускации по пресету.
    Возвращает dict с ключами: jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4, i1..i5
    (при protocol_version="3.1" — плюс 9 ключей 3.1: header_protection_key,
    content_padding_addition, rekey_*, reject_after_time, keepalive_timeout,
    max_handshake_attempts, random_trailers, disable_cookies).

    protocol_version="3.1" (AWG 3.1, v5.5) — диапазоны сужаются до констрейнтов
    GenerateObfuscation31 (как в wpp_awg.py):
      • S1/S2 15-150, S3 12-55, S4 12-27 (S-паддинг ≥ 12 под HeaderProtectionKey);
      • Jmin 40-89, Jmax = Jmin + 50..250 (≤ 339);
      • H1-H4 — одиночные int в НЕПЕРЕСЕКАЮЩИХСЯ бандах от 5 (не диапазоны
        "N-M": 3.1-генератор 3x-ui использует одиночные значения);
      • I1 — ВСЕГДА CPS-тег «<r N>» (N 32-256), независимо от i1_mode пресета
        (в 3.1 I1 обязателен; binary/quic_mimicry — 2.0-специфика);
      • + 9 дополнительных параметров 3.1 (см. awg_protocol).

    Jc/Jmin/Jmax — случайные в per-preset диапазонах (DPI-тюнинг под
    конкретного оператора, см. AWGS_CARRIER_PRESETS). I1 — per-preset
    режим (random/absent/binary). S1, S2 остаются 0 (как в bivlked).

    S3, S4 — случайные в общих диапазонах 0..AWGS_S3_MAX / 0..AWGS_S4_MAX
    (это общегигиенические параметры, не связанные с тюнингом под
    конкретного оператора). Диапазоны переиспользуются из
    _FULL_MANUAL_RANGES чтобы не дублировать константы.

    H1-H4 — генерируются как НЕПЕРЕСЕКАЮЩИЕСЯ случайные значения в
    1.._H_UPPER_LIMIT (та же логика, что в
    awgs_generate_full_manual_params(), см. _generate_non_overlapping_h_values).
    Раньше H1-H4 были захардкожены как 1,2,3,4 во всех пресетах — это
    давало одинаковый DPI-отпечаток всем установкам проекта на одном
    пресете (подтверждено пользователем zvshka: byte-identical S1-S4/H1-H4
    на разных серверах с Default preset).

    I2-I5 — пустые по умолчанию для пресетного пути (опциональные
    decoy-пакеты; полный контроль даёт пункт «5. Ручная настройка»).

    Каждый вызов (install/rotation) генерирует НОВЫЕ уникальные
    S3/S4/H1-H4 — это явно требуется для «Обновить параметры обфускации»
    в меню (awgs_rotate_obfuscation).
    """
    preset = AWGS_CARRIER_PRESETS.get(name)
    if not preset:
        raise ValueError(f"Неизвестный пресет: '{name}'. "
                         f"Допустимые: {', '.join(AWGS_CARRIER_PRESETS.keys())}")

    is_31 = awg_is_31(protocol_version)

    # Jc — случайное целое в per-preset диапазоне
    jc = random.randint(preset["jc_min"], preset["jc_max"])

    # Jmin — случайное целое в per-preset диапазоне; для 3.1 дополнительно
    # ограничиваем 40-89 (констрейнт GenerateObfuscation31: Jmax ≤ 339)
    # Если пересечение диапазонов пусто (например tmobile_us jmin=10-10 < 40)
    # — fallback на глобальный 3.1-диапазон 40-89.
    if is_31:
        _lo = max(preset["jmin_min"], 40)
        _hi = min(preset["jmin_max"], 89)
        if _lo > _hi:
            _lo, _hi = 40, 89
        jmin = random.randint(_lo, _hi)
    else:
        jmin = random.randint(preset["jmin_min"], preset["jmin_max"])

    # Jmax = Jmin + delta (delta в per-preset диапазоне; для 3.1 — ≤ 339)
    jmax_delta = random.randint(preset["jmax_delta_min"], preset["jmax_delta_max"])
    if is_31:
        jmax_delta = min(jmax_delta, 250)
    jmax = jmin + jmax_delta

    # S1, S2 — случайные ненулевые (как в эталонном конфиге Amnezia).
    # v5.4.2: РАНЬШЕ были 0 (как в bivlked). Но рабочий конфиг от приложения
    # Amnezia использует S1=125, S2=47 — ненулевые. Подтверждено zvshka:
    # с S1=0, S2=0 handshake не завершается. С ненулевыми S1/S2 — работает.
    # S1/S2 — это junk packet size для init/response фазы handshake.
    # Нулевое значение может вызывать сбой на некоторых реализациях AWG.
    #
    # AWG 3.1: S1/S2 15-150 (S ≥ 12 под HeaderProtectionKey), S3 12-55,
    # S4 12-27 — как в GenerateObfuscation31 (wpp_awg._parameters).
    if is_31:
        s1 = random.randint(15, 150)
        s2 = random.randint(15, 150)
    else:
        s1 = random.randint(_FULL_MANUAL_RANGES["s1"][0], _FULL_MANUAL_RANGES["s1"][1])
        s2 = random.randint(_FULL_MANUAL_RANGES["s2"][0], _FULL_MANUAL_RANGES["s2"][1])
    # Правило S1 + 56 != S2 (паттерн, выдающий VPN) — перегенерация при коллизии
    for _attempt in range(10):
        if s1 + 56 != s2:
            break
        s2 = random.randint(15, 150) if is_31 else random.randint(
            _FULL_MANUAL_RANGES["s2"][0], _FULL_MANUAL_RANGES["s2"][1])

    # S3, S4 — случайные в общих диапазонах (общегигиенические, не per-preset).
    # Переиспользуем диапазоны из _FULL_MANUAL_RANGES чтобы не дублировать.
    if is_31:
        s3 = random.randint(12, 55)
        s4 = random.randint(12, 27)
    else:
        s3 = random.randint(_FULL_MANUAL_RANGES["s3"][0], _FULL_MANUAL_RANGES["s3"][1])
        s4 = random.randint(_FULL_MANUAL_RANGES["s4"][0], _FULL_MANUAL_RANGES["s4"][1])

    # H1-H4 — непересекающиеся случайные значения (см. комментарий выше).
    # AWG 3.1: одиночные int в бандах от 5 (GenerateObfuscation31-стиль),
    # НЕ диапазоны "N-M" — как в wpp_awg._parameters (референс 3.1 в проде).
    if is_31:
        h1, h2, h3, h4 = _generate_non_overlapping_h_values_31()
    else:
        h1, h2, h3, h4 = _generate_non_overlapping_h_values()

    # I1 — зависит от per-preset i1_mode.
    #
    # AWG 3.1: I1 ВСЕГДА «<r N>» с N 32-256 (GenerateObfuscation31;
    # i1_mode пресета игнорируется — в 3.1 I1 обязателен, а binary/
    # quic_mimicry — 2.0-специфика).
    #
    # v5.1: I1 теперь генерируется в CPS tag-формате (AWG 2.0), а НЕ как
    # голая hex-строка. Сравнение с конфигом официального приложения
    # Amnezia показало, что голый hex — это старый формат AWG 1.5, а
    # AWG 2.0 требует теговый мини-язык: <b 0x...>, <r N>, <t> и т.д.
    # (см. docs.amnezia.org и bivlked/amneziawg-installer/ADVANCED.md).
    # Некоторые клиенты (Keenetic native AWG 2.0, amneziawg-go) падают
    # на голом hex-формате с невнятной ошибкой "туннель подключается,
    # но трафик не идёт".
    if is_31:
        i1_size = random.randint(32, 256)
        i1 = f"<r {i1_size}>"
    else:
        i1_mode = preset["i1_mode"]
        if i1_mode == "random":
            # Случайные N байт — простейший валидный CPS-формат, функционально
            # эквивалентен старому голому hex-снапшоту (та же энтропия), но
            # синтаксически корректный для AWG 2.0.
            i1_size = random.randint(24, 32)
            i1 = f"<r {i1_size}>"
        elif i1_mode == "binary":
            # Статичные байты в CPS-формате <b 0x...> — для T-Mobile US
            # (короткий фиксированный blob, как в upstream preset).
            i1_hex = "".join(random.choices("0123456789abcdef", k=32))
            i1 = f"<b 0x{i1_hex}>"
        elif i1_mode == "quic_mimicry":
            # QUIC Initial packet mimicry — маскировка под QUIC v1 long-header.
            # Используется опционально для sneaky-режима (см. bivlked-гайд).
            i1 = _generate_quic_mimicry_i1()
        else:  # absent
            i1 = ""

    # I2-I5 — пустые (опциональные decoy-пакеты)
    i2 = i3 = i4 = i5 = ""

    params = {
        "jc":   jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1":   s1, "s2": s2, "s3": s3, "s4": s4,
        "h1":   h1, "h2": h2, "h3": h3, "h4": h4,
        "i1":   i1, "i2": i2, "i3": i3, "i4": i4, "i5": i5,
    }

    # AWG 3.1: добавляем 9 транспортных параметров (HeaderProtectionKey и т.д.)
    if is_31:
        params = awg31_merge_into_params(params)

    return params


# ── H1-H4 для AWG 3.1 (GenerateObfuscation31-стиль) ─────────────────────────

def _generate_non_overlapping_h_values_31():
    """Генерирует H1-H4 для AWG 3.1 — одиночные int в НЕПЕРЕСЕКАЮЩИХСЯ бандах.

    Как в GenerateObfuscation31 (3x-ui 3.8.5) и wpp_awg._parameters:
    каждое H-значение получает свой band в [5, INT32_MAX], диапазоны
    физически не пересекаются. Значения 1-4 не используются — это
    узнаваемые vanilla-WireGuard типы сообщений (init/response/cookie/
    transport).
    """
    h_low = 5
    h_band = (2147483647 - h_low + 1) // 4
    return tuple(
        random.randint(h_low + i * h_band, h_low + (i + 1) * h_band - 1)
        for i in range(4)
    )


def awgs_presets_validate_params(params: dict, protocol_version: str = AWG_VERSION_20) -> tuple[bool, str]:
    """
    Валидирует параметры обфускации.
    Возвращает (ok, error_message).
    Перенесено из validate_jc_value/validate_junk_size в bivlked + расширено
    для S1/S2 (нет явного max в bivlked, используем 1280 как для Jmin/Jmax)
    и H1-H4 (0-255, magic header byte).

    protocol_version="3.1": дополнительно проверяются 9 параметров 3.1
    (HeaderProtectionKey/ContentPaddingAddition/Rekey*/...) через
    awg_protocol.awg31_validate_extra_params, S1-S4 ≥ 12, Jmax ≤ 339,
    I1 — строго «<r N>» (GenerateObfuscation31-констрейнты; см. wpp_awg).
    """
    from .awg_constants import (
        AWGS_JC_MIN, AWGS_JC_MAX, AWGS_JMIN_MAX, AWGS_JMAX_MAX,
        AWGS_S3_MAX, AWGS_S4_MAX, AWGS31_JMAX_MAX,
    )
    is_31 = awg_is_31(protocol_version)

    # Jc: 1-128
    jc = params.get("jc", 0)
    if not isinstance(jc, int) or jc < AWGS_JC_MIN or jc > AWGS_JC_MAX:
        return False, f"Jc={jc} вне диапазона ({AWGS_JC_MIN}-{AWGS_JC_MAX})"

    # Jmin: 0-1280
    jmin = params.get("jmin", 0)
    if not isinstance(jmin, int) or jmin < 0 or jmin > AWGS_JMIN_MAX:
        return False, f"Jmin={jmin} вне диапазона (0-{AWGS_JMIN_MAX})"

    # Jmax: 0-1280, >= Jmin; для 3.1 — ≤ 339 (констрейнт GenerateObfuscation31)
    jmax = params.get("jmax", 0)
    if not isinstance(jmax, int) or jmax < 0 or jmax > AWGS_JMAX_MAX:
        return False, f"Jmax={jmax} вне диапазона (0-{AWGS_JMAX_MAX})"
    if jmax < jmin:
        return False, f"Jmax ({jmax}) меньше Jmin ({jmin})"
    if is_31 and jmax > AWGS31_JMAX_MAX:
        return False, f"Jmax={jmax} вне диапазона AWG 3.1 (0-{AWGS31_JMAX_MAX})"

    # S1, S2: 0-1280 (junk size, как Jmin/Jmax); для 3.1 — 15-150
    for key in ("s1", "s2"):
        v = params.get(key, 0)
        if not isinstance(v, int) or v < 0 or v > AWGS_JMIN_MAX:
            return False, f"{key.upper()}={v} вне диапазона (0-{AWGS_JMIN_MAX})"
        if is_31 and not (15 <= v <= 150):
            return False, f"{key.upper()}={v} вне диапазона AWG 3.1 (15-150)"

    # S3: 0-64; для 3.1 — 12-55
    s3 = params.get("s3", 0)
    if not isinstance(s3, int) or s3 < 0 or s3 > AWGS_S3_MAX:
        return False, f"S3={s3} вне диапазона (0-{AWGS_S3_MAX})"
    if is_31 and not (12 <= s3 <= 55):
        return False, f"S3={s3} вне диапазона AWG 3.1 (12-55)"

    # S4: 0-32; для 3.1 — 12-27
    s4 = params.get("s4", 0)
    if not isinstance(s4, int) or s4 < 0 or s4 > AWGS_S4_MAX:
        return False, f"S4={s4} вне диапазона (0-{AWGS_S4_MAX})"
    if is_31 and not (12 <= s4 <= 27):
        return False, f"S4={s4} вне диапазона AWG 3.1 (12-27)"

    # H1-H4: magic headers. По официальной документации AmneziaWG
    # (docs.amnezia.org) безопасный верхний предел — INT32_MAX (2147483647).
    # amneziawg-windows-client может подсвечивать значения выше как invalid.
    # v5.3: поддерживаем ДВА формата (как в эталонном конфиге Amnezia):
    #   1. Одиночное число: H1 = 12345
    #   2. Диапазон N-M: H1 = 2135087609-2145903954 (как в официальном Amnezia)
    # Диапазонный формат скрывает magic header — DPI не может написать
    # универсальное правило для детекции. Подтверждено эталонным конфигом
    # из Docker-контейнера Amnezia (zvshka).
    #  расширено с 0-255 до 0-INT32_MAX.
    _H_MAX = 2147483647  # INT32_MAX
    _H_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")
    for key in ("h1", "h2", "h3", "h4"):
        v = params.get(key, 0)
        # Принимаем int (одиночное число)
        if isinstance(v, int):
            if v < 0 or v > _H_MAX:
                return False, f"{key.upper()}={v} вне диапазона (0-{_H_MAX})"
            continue
        # Принимаем строку — одиночное число или диапазон N-M
        if isinstance(v, str):
            v_str = v.strip()
            # Проверяем диапазон N-M
            m = _H_RANGE_RE.match(v_str)
            if m:
                lo = int(m.group(1))
                hi = int(m.group(2))
                if lo < 0 or lo > _H_MAX:
                    return False, f"{key.upper()}={v} начало диапазона вне (0-{_H_MAX})"
                if hi < 0 or hi > _H_MAX:
                    return False, f"{key.upper()}={v} конец диапазона вне (0-{_H_MAX})"
                if lo > hi:
                    return False, f"{key.upper()}={v} начало диапазона > конца"
                continue
            # Проверяем одиночное число как строку
            try:
                v_int = int(v_str)
                if v_int < 0 or v_int > _H_MAX:
                    return False, f"{key.upper()}={v} вне диапазона (0-{_H_MAX})"
                continue
            except ValueError:
                return False, f"{key.upper()}={v} не число и не диапазон N-M"
        # Любой другой тип
        return False, f"{key.upper()}={v} должен быть int или строкой 'N' или 'N-M'"

    # I1-I5: опциональные CPS tag-строки (AWG 2.0) или голый hex (AWG 1.5,
    # для обратной совместимости со старыми state.json).
    #
    # v5.1: раньше валидатор принимал только голый hex. Теперь I1-I5
    # генерируются в CPS tag-формате (<r N>, <b 0x...>, <t> и т.д.) —
    # это спецификация AWG 2.0 (docs.amnezia.org). Старый hex-формат
    # оставляем валидным для обратной совместимости, чтобы не сломать
    # уже установленные конфиги пользователей.
    # См. _is_valid_cps_or_legacy_hex() для деталей формата.
    for key in ("i1", "i2", "i3", "i4", "i5"):
        v = params.get(key, "")
        if v and not isinstance(v, str):
            return False, f"{key.upper()} должен быть строкой"
        if v and not _is_valid_cps_or_legacy_hex(v):
            return False, (f"{key.upper()} содержит невалидные символы. "
                          f"Ожидается CPS tag-формат AWG 2.0 "
                          f"(<b 0x...>, <r N>, <t>) или голый hex (AWG 1.5). "
                          f"Фактически: {v[:64]}{'...' if len(v) > 64 else ''}")

    # AWG 3.1: I1 — строго «<r N>» (GenerateObfuscation31; binary-blob и
    # quic_mimicry — 2.0-специфика, в 3.1 I1 обязан быть random-тегом).
    if is_31:
        i1 = params.get("i1", "")
        if not (isinstance(i1, str) and i1.startswith("<r ") and i1.endswith(">")):
            return False, ("I1 в AWG 3.1 должен быть CPS-тегом '<r N>' "
                           f"(фактически: {str(i1)[:32]!r})")

    # AWG 3.1: 9 дополнительных параметров (HeaderProtectionKey и т.д.)
    if is_31:
        ok31, err31 = awg31_validate_extra_params(params)
        if not ok31:
            return False, f"AWG 3.1: {err31}"

    return True, ""


def awgs_presets_compare_with_carrier(
    current_params: dict, carrier: str
) -> dict:
    """
    Сравнивает текущие параметры сервера с профилем оператора.
    Возвращает dict со статусом и diff'ом.
    Используется в diagnose (--carrier=NAME).
    """
    preset = AWGS_CARRIER_PRESETS.get(carrier)
    if not preset:
        return {
            "ok": False,
            "error": f"Неизвестный оператор: '{carrier}'. "
                     f"Допустимые: {', '.join(AWGS_CARRIER_PRESETS.keys())}"
        }

    # Текущие значения
    cur_jc = current_params.get("jc", 0)
    cur_jmin = current_params.get("jmin", 0)
    cur_jmax = current_params.get("jmax", 0)
    cur_i1 = current_params.get("i1", "")

    # Ожидаемые диапазоны
    exp_jc_range = (preset["jc_min"], preset["jc_max"])
    exp_jmin_range = (preset["jmin_min"], preset["jmin_max"])
    exp_jmax_range = (
        preset["jmin_min"] + preset["jmax_delta_min"],
        preset["jmin_max"] + preset["jmax_delta_max"],
    )
    exp_i1_mode = preset["i1_mode"]

    # Проверки
    checks = []

    # Jc
    if exp_jc_range[0] == exp_jc_range[1]:
        if cur_jc == exp_jc_range[0]:
            checks.append(("Jc", "OK", f"Jc={cur_jc} (ожидается {exp_jc_range[0]})"))
        else:
            checks.append(("Jc", "FAIL", f"Jc={cur_jc} (ожидается {exp_jc_range[0]})"))
    else:
        if exp_jc_range[0] <= cur_jc <= exp_jc_range[1]:
            checks.append(("Jc", "OK", f"Jc={cur_jc} (диапазон {exp_jc_range[0]}-{exp_jc_range[1]})"))
        else:
            checks.append(("Jc", "FAIL", f"Jc={cur_jc} вне диапазона {exp_jc_range[0]}-{exp_jc_range[1]}"))

    # Jmin
    if exp_jmin_range[0] <= cur_jmin <= exp_jmin_range[1]:
        checks.append(("Jmin", "OK", f"Jmin={cur_jmin} (диапазон {exp_jmin_range[0]}-{exp_jmin_range[1]})"))
    else:
        checks.append(("Jmin", "FAIL", f"Jmin={cur_jmin} вне диапазона {exp_jmin_range[0]}-{exp_jmin_range[1]}"))

    # Jmax
    if exp_jmax_range[0] <= cur_jmax <= exp_jmax_range[1]:
        checks.append(("Jmax", "OK", f"Jmax={cur_jmax} (диапазон {exp_jmax_range[0]}-{exp_jmax_range[1]})"))
    else:
        checks.append(("Jmax", "WARN", f"Jmax={cur_jmax} вне диапазона {exp_jmax_range[0]}-{exp_jmax_range[1]}"))

    # I1
    if exp_i1_mode == "absent":
        if not cur_i1:
            checks.append(("I1", "OK", "I1 отсутствует (требуется для этого оператора)"))
        else:
            checks.append(("I1", "WARN", f"I1 задан ({cur_i1[:16]}...) — оператор требует отсутствие I1"))
    elif exp_i1_mode == "random":
        if cur_i1:
            checks.append(("I1", "OK", f"I1 задан ({cur_i1[:16]}...)"))
        else:
            checks.append(("I1", "WARN", "I1 отсутствует — оператор ожидает случайный I1"))
    elif exp_i1_mode == "binary":
        if cur_i1:
            checks.append(("I1", "OK", f"I1 задан (binary)"))
        else:
            checks.append(("I1", "WARN", "I1 отсутствует — оператор ожидает binary I1"))

    # Итог
    has_fail = any(s == "FAIL" for _, s, _ in checks)
    has_warn = any(s == "WARN" for _, s, _ in checks)
    if has_fail:
        status = "FAIL"
    elif has_warn:
        status = "WARN"
    else:
        status = "OK"

    return {
        "ok":       status != "FAIL",
        "status":   status,
        "carrier":  carrier,
        "label":    preset["label"],
        "checks":   checks,
    }


# ============================================================================
#  ПОЛНАЯ РУЧНАЯ ГЕНЕРАЦИЯ  — отдельный путь, не связан с пресетами
# ============================================================================
# Жалоба пользователя (Keenetic не может импортировать AWG-конфиг) вскрыла
# две проблемы:
#
# 1. Cascade-режим (awg_transport.py) генерил только 9 параметров
#    (Jc/Jmin/Jmax/S1/S2/H1-H4) — без S3/S4/I1-I5. Keenetic, видимо,
#    парсер-строгий и падал на отсутствии I1.
#
# 2. H1-H4 хардкожены как 1,2,3,4 ВЕЗДЕ (в пресетах и в Cascade) — это
#    узнаваемый DPI-отпечаток проекта. По официальной документации Amnezia
#    H1-H4 должны быть УНИКАЛЬНЫ для каждого развёртывания.
#
# Эта функция — параллельный путь для "полного ручного набора" или
# "полного авто-набора" (3-й пункт в меню выбора обфускации). Она НЕ
# заменяет и НЕ трогает awgs_presets_generate() — пресеты операторов
# остаются как есть, со своими H1-H4=1,2,3,4 (это сознательное решение
# автора пресетов, см. комментарий в AWGS_CARRIER_PRESETS).
#
# Ключевые отличия от awgs_presets_generate():
#   - H1-H4 — НЕПЕРЕСЕКАЮЩИЕСЯ случайные диапазоны в 1..INT32_MAX
#     (а не фиксированные 1,2,3,4)
#   - S3, S4 — случайные в рекомендованных диапазонах (0-64 / 0-32),
#     не обязательно 0
#   - I1 — hex 48-64 символа (как i1_mode=random в пресетах)
#   - I2-I5 — пустые по умолчанию, но принимают override
#   - Правило S1 + 56 != S2 проверяется и перегенерируется при коллизии

# Безопасный верхний предел для H1-H4 по официальной документации Amnezia
# (docs.amnezia.org). amneziawg-windows-client может подсвечивать значения
# выше INT32_MAX как invalid.
_H_UPPER_LIMIT: int = 2147483647  # INT32_MAX


def _generate_non_overlapping_h_value(used_h: set[int]) -> int:
    """Генерирует одно случайное значение H в диапазоне 1.._H_UPPER_LIMIT,
    гарантированно не входящее в ``used_h``.

    Используется как awgs_presets_generate() (для всех carrier-пресетов),
    так и awgs_generate_full_manual_params() — общая логика анти-фингерпринта
    (H1-H4 должны быть непересекающимися между собой, иначе DPI может
    написать универсальное правило для детекции именно этого проекта).

    Делает до 50 случайных попыток; если все 50 совпали с used_h (почти
    невозможно для INT32_MAX), падает на детерминистический инкремент от 1.
    """
    for _attempt in range(50):
        hv = random.randint(1, _H_UPPER_LIMIT)
        if hv not in used_h:
            return hv
    # 50 попыток не хватило (невероятно для INT32_MAX) — берём
    # любое непересекающееся через инкремент
    hv = 1
    while hv in used_h:
        hv += 1
        if hv > _H_UPPER_LIMIT:
            hv = 1
    return hv


def _generate_non_overlapping_h_ranges(used_ranges: list[tuple[int, int]],
                                       range_size: int = 1000) -> tuple[int, int]:
    """Генерирует один непересекающийся диапазон [start, end] для H1-H4.

    v5.3: официальный Amnezia использует формат H1 = N-M (диапазон, не
    одиночное число) — это скрывает magic header в диапазоне, DPI не может
    написать универсальное правило для детекции. Подтверждено эталонным
    конфигом из Docker-контейнера Amnezia (zvshka):
      H1 = 2135087609-2145903954
      H2 = 2147225277-2147461177
      H3 = 2147472979-2147474536
      H4 = 2147478893-2147482205

    Генерирует диапазон [start, start+range_size-1], где start случайно.
    Проверяет что диапазон не пересекается ни с одним из used_ranges.
    Возвращает кортеж (start, end) где end = start + range_size - 1.

    Диапазоны располагаются в верхней части INT32_MAX (как в эталонном
    конфиге Amnezia) — значения близкие к INT32_MAX, но не превышающие.
    range_size=1000 — компромисс между анти-DPI эффективностью (большой
    диапазон сложнее fingerprint'ить) и совместимостью (не все клиенты
    принимают очень большие диапазоны).
    """
    # Делаем до 50 попыток найти непересекающийся диапазон
    for _attempt in range(50):
        # start в верхней трети INT32_MAX (как в эталонном Amnezia конфиге)
        # Оставляем запас для range_size чтобы не превысить INT32_MAX
        lo = _H_UPPER_LIMIT - _H_UPPER_LIMIT // 3
        hi = _H_UPPER_LIMIT - range_size
        start = random.randint(lo, hi)
        end = start + range_size - 1
        # Проверяем непересечение с существующими диапазонами
        overlaps = False
        for (u_start, u_end) in used_ranges:
            if not (end < u_start or start > u_end):
                overlaps = True
                break
        if not overlaps:
            return (start, end)
    # 50 попыток не хватило — берём инкрементальный подход
    # Ищем первый свободный слот начиная с lo
    start = lo
    while True:
        end = start + range_size - 1
        if end > _H_UPPER_LIMIT:
            start = lo
            end = start + range_size - 1
        overlaps = False
        for (u_start, u_end) in used_ranges:
            if not (end < u_start or start > u_end):
                overlaps = True
                break
        if not overlaps:
            return (start, end)
        start += range_size + 1


def _generate_non_overlapping_h_values() -> tuple:
    """Генерирует 4 непересекающихся диапазона H1-H4 в формате 'N-M'.

    v5.4.2: Диапазоны H1-H4 ПОДДЕРЖИВАЮТСЯ всеми версиями amneziawg-tools
    (подтверждено zvshka: рабочая конфигурация Amnezia с диапазонами
    работает на его сервере со старыми amneziawg-tools). Убираем
    условную проверку awgs_supports_h_ranges() — всегда генерируем
    диапазоны.

    Диапазонный формат скрывает magic header — DPI не может написать
    универсальное правило для детекции именно этого проекта (раньше
    одиночные числа были узнаваемым отпечатком).
    """
    used_ranges: list[tuple[int, int]] = []
    result = []
    for _ in range(4):
        start, end = _generate_non_overlapping_h_ranges(used_ranges)
        used_ranges.append((start, end))
        result.append(f"{start}-{end}")
    return tuple(result)


# ── CPS tag-формат для I1-I5 (AWG 2.0) ──────────────────────────────────────
# I1-I5 — это мини-язык тегов (Custom Protocol Signature), задокументированный
# в docs.amnezia.org и спецификации amneziawg-go. Каждый I-параметр — это
# последовательность тегов, которые в рантайме разворачиваются в байты.
# v5.1: раньше генерировался голый hex (старый формат AWG 1.5) — некоторые
# клиенты (Keenetic native AWG 2.0, amneziawg-go) на это падают.

# Regex для проверки CPS-тегов в валидаторе. Допускаем:
#   <b 0x[hex]>           — статичные байты (hex, обязательно чётное число символов)
#   <r [size]>            — [size] случайных байт
#   <rd [size]>           — [size] случайных байт из [0-9]
#   <rc [size]>           — [size] случайных байт из [a-zA-Z]
#   <t>                   — 4-байтный текущий unix-timestamp
# Также допускаем whitespace между тегами (как в официальном примере Amnezia).
# Голый hex без тегов НЕ валиден для AWG 2.0, но оставляем толерантность
# для обратной совместимости — если у пользователя в state.json остался
# старый hex-I1 (до v5.1), валидатор не должен его отбрасывать, чтобы
# не сломать уже установленные конфиги (правка только для НОВОЙ генерации).
_CPS_TAG_RE = re.compile(
    r"^(\s*"
    r"<b\s+0x[0-9a-fA-F]+>"
    r"|<r[d c]?\s+\d+>"
    r"|<t>"
    r")+\s*$"
)

# Альтернативный «legacy hex» паттерн — голый hex без тегов. Допускаем
# в валидаторе для обратной совместимости с уже установленными конфигами
# (v5.0 и ранее), но новая генерация его больше не использует.
_LEGACY_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _is_valid_cps_or_legacy_hex(value: str) -> bool:
    """Проверяет, является ли value корректным I1-I5 значением.

    Принимает два формата:
      1. CPS tag-формат AWG 2.0 (``<b 0x...>``, ``<r N>``, ``<t>`` и т.д.) —
         НОВЫЙ формат, генерируется начиная с v5.1.
      2. Голый hex без тегов — СТАРЫЙ формат AWG 1.5, остаётся в валидаторе
         для обратной совместимости с уже установленными конфигами
         (state.json у пользователей, которые обновились с  ).
         Новая генерация этот формат больше НЕ использует.

    Пустая строка считается валидной (I1-I5 опциональны).
    None и non-string значения НЕ валидны (в отличие от пустой строки,
    которая semantically означает "не задано").
    """
    if not isinstance(value, str):
        return False
    if value == "":
        return True
    if _CPS_TAG_RE.match(value):
        return True
    if _LEGACY_HEX_RE.match(value):
        return True
    return False


def _generate_quic_mimicry_i1() -> str:
    """Генерирует I1 в формате QUIC Initial packet mimicry.

    Паттерн из bivlked/amneziawg-installer (ADVANCED.md) и комьюнити-гайдов:
      <b 0xc30000000108><r 8><b 0x08><r 8><b 0x0045dc><t><r 16>

    Байты ``0xc3+версия`` имитируют QUIC v1 long-header (RFC 9000):
      0xc3 = Long header flag (1100 0011):
        - 1 = long header (1 bit)
        - 1 = fixed bit (must be 1 for valid QUIC packets)
        - 0 = unused
        - 0011 = QUIC version 1
      00000001 = connection ID length
      08 = packet number length
      0045dc = reserved version-specific bytes

    Дальше идут случайные байты (через ``<r N>``) и текущий timestamp
    (через ``<t>``), чтобы каждый handshake выглядел как реальный QUIC
    packet с уникальными connection-ID и packet-number.

    НЕ меняется между вызовами — паттерн статичный (только рантайм-теги
    ``<r N>`` и ``<t>`` дают уникальность при каждом handshake).
    """
    return "<b 0xc30000000108><r 8><b 0x08><r 8><b 0x0045dc><t><r 16>"


# Рекомендованные диапазоны для авто-генерации (взяты из спеки AWG 2.0
# и bivlked/amneziawg-installer/ADVANCED.md). Эти диапазоны НЕ используют
# carrier-специфичные значения из AWGS_CARRIER_PRESETS — это нейтральные
# "универсальные" значения для случая, когда пользователь не выбрал
# конкретного оператора.
_FULL_MANUAL_RANGES: dict = {
    "jc":   (3, 10),       # рекомендованный диапазон (часто 3-6)
    "jmin": (40, 90),      # рекомендованный диапазон
    # jmax = jmin + delta, delta в диапазоне 50-250
    "jmax_delta": (50, 250),
    "s1":   (0, 32),       # 0-32 байта (было в проекте ранее)
    "s2":   (0, 32),       # 0-32 байта
    "s3":   (0, 64),       # добавлены в AWG 2.0 позже S1/S2
    "s4":   (0, 32),       # 0-32 байта
}


def awgs_generate_full_manual_params(overrides: dict | None = None,
                                     protocol_version: str = AWG_VERSION_20) -> dict:
    """Генерирует ПОЛНЫЙ набор параметров AWG (все 16: Jc/Jmin/Jmax/
    S1-S4/H1-H4/I1-I5 — а при protocol_version="3.1" плюс 9 транспортных
    параметров 3.1) со случайными значениями в рекомендованных
    диапазонах по умолчанию.

    protocol_version="3.1": S1/S2 15-150, S3 12-55, S4 12-27, Jmin 40-89,
    Jmax ≤ 339, H1-H4 — одиночные int в бандах от 5, I1 = «<r 32-256>»,
    + HeaderProtectionKey/ContentPaddingAddition/Rekey*/RejectAfterTime/
    KeepaliveTimeout/MaxHandshakeAttempts/RandomTrailers/DisableCookies
    (констрейнты GenerateObfuscation31, см. awg_protocol).

    overrides — словарь с значениями, явно введёнными пользователем
    интерактивно (см. awgs_prompt_custom_params в awg_standalone.py).
    Если ключ присутствует в overrides — использовать его значение
    вместо случайного; если нет — сгенерировать случайное в рекомендо-
    ванном диапазоне.

    H1-H4 генерируются как НЕПЕРЕСЕКАЮЩИЕСЯ случайные значения в
    диапазоне 1.._H_UPPER_LIMIT (INT32_MAX). Это отличие от пресетов,
    где H1-H4=1,2,3,4 фиксированы — здесь каждое развёртывание получает
    уникальные значения, что не даёт DPI написать универсальное правило
    для детекции именно этого проекта.

    I1 — CPS tag-строка формата AWG 2.0 (``<r N>`` по умолчанию,
    24-32 случайных байт). v5.1: раньше генерировался голый hex (AWG 1.5),
    но он ломает некоторых клиентов (Keenetic native AWG 2.0, amneziawg-go).
    Override принимается as-is — если пользователь явно ввёл ``<b 0x...>``
    или голый hex, валидатор оба примет (см. _is_valid_cps_or_legacy_hex).
    I2-I5 — по умолчанию пустые, но принимают override.

    Правило совместимости S1 + 56 != S2 проверяется при генерации —
    если случайно совпало (padded init и padded response совпадут по
    размеру, что выдаёт VPN), S2 перегенерируется.

    Возвращает dict с 16 ключами: jc/jmin/jmax/s1-s4/h1-h4/i1-i5.
    Формат совпадает с awgs_presets_generate() — можно передавать
    в awgs_presets_validate_params() и в awgs_build_server_conf().
    """
    overrides = overrides or {}
    r = _FULL_MANUAL_RANGES
    is_31 = awg_is_31(protocol_version)

    # ── Jc ────────────────────────────────────────────────────────────────
    if "jc" in overrides:
        jc = int(overrides["jc"])
    else:
        jc = random.randint(r["jc"][0], r["jc"][1])

    # ── Jmin/Jmax ─────────────────────────────────────────────────────────
    # AWG 3.1: Jmin 40-89, Jmax ≤ 339 (GenerateObfuscation31)
    if "jmin" in overrides:
        jmin = int(overrides["jmin"])
    elif is_31:
        jmin = random.randint(40, 89)
    else:
        jmin = random.randint(r["jmin"][0], r["jmin"][1])

    if "jmax" in overrides:
        jmax = int(overrides["jmax"])
    elif is_31:
        jmax = jmin + random.randint(50, 250)
    else:
        jmax_delta = random.randint(r["jmax_delta"][0], r["jmax_delta"][1])
        jmax = jmin + jmax_delta
    # Safety: Jmax должен быть >= Jmin
    if jmax < jmin:
        jmax = jmin

    # ── S1, S2 (с правилом S1 + 56 != S2) ─────────────────────────────────
    # AWG 3.1: S1/S2 15-150 (S >= 12 под HeaderProtectionKey)
    _s1_lo, _s1_hi = (15, 150) if is_31 else (r["s1"][0], r["s1"][1])
    _s2_lo, _s2_hi = (15, 150) if is_31 else (r["s2"][0], r["s2"][1])

    if "s1" in overrides:
        s1 = int(overrides["s1"])
    else:
        s1 = random.randint(_s1_lo, _s1_hi)

    if "s2" in overrides:
        s2 = int(overrides["s2"])
    else:
        # Перегенерируем S2 если S1 + 56 == S2 (паттерн, выдающий VPN)
        # Делаем до 10 попыток, потом принудительно сдвигаем.
        s2 = random.randint(_s2_lo, _s2_hi)
        for _attempt in range(10):
            if s1 + 56 != s2:
                break
            s2 = random.randint(_s2_lo, _s2_hi)
        else:
            # Все 10 попыток совпали (маловероятно) — принудительно
            # сдвигаем S2 на 1 от S1+56.
            s2 = (s1 + 57) & 0xFFFFFFFF
            if s2 > _s2_hi:
                s2 = _s2_hi if _s2_hi != (s1 + 56) else _s2_lo

    # ── S3, S4 ────────────────────────────────────────────────────────────
    # AWG 3.1: S3 12-55, S4 12-27 (GenerateObfuscation31)
    _s3_lo, _s3_hi = (12, 55) if is_31 else (r["s3"][0], r["s3"][1])
    _s4_lo, _s4_hi = (12, 27) if is_31 else (r["s4"][0], r["s4"][1])

    if "s3" in overrides:
        s3 = int(overrides["s3"])
    else:
        s3 = random.randint(_s3_lo, _s3_hi)

    if "s4" in overrides:
        s4 = int(overrides["s4"])
    else:
        s4 = random.randint(_s4_lo, _s4_hi)

    # ── H1-H4 — непересекающиеся диапазоны в формате 'N-M' (AWG 2.0) ─────
    # v5.4.2: Всегда генерируем диапазоны (подтверждено zvshka — работает).
    # Overrides: если пользователь явно ввёл H1-H4, используем как есть.
    # AWG 3.1: одиночные int в НЕПЕРЕСЕКАЮЩИХСЯ бандах от 5
    # (GenerateObfuscation31-стиль, как в wpp_awg) — не диапазоны.
    if is_31 and not any(k in overrides for k in ("h1", "h2", "h3", "h4")):
        h1, h2, h3, h4 = (str(v) for v in _generate_non_overlapping_h_values_31())
    else:
        h_overrides = []
        for key in ("h1", "h2", "h3", "h4"):
            if key in overrides:
                hv = str(overrides[key])
                h_overrides.append((key, hv))

        used_ranges: list[tuple[int, int]] = []
        # Парсим overrides в диапазоны для проверки пересечений
        for key, hv in h_overrides:
            if "-" in hv:
                parts = hv.split("-")
                used_ranges.append((int(parts[0]), int(parts[1])))
            else:
                v = int(hv)
                used_ranges.append((v, v))
        # Заполняем остальные (без override)
        for key in ("h1", "h2", "h3", "h4"):
            if key in overrides:
                continue
            start, end = _generate_non_overlapping_h_ranges(used_ranges)
            used_ranges.append((start, end))
            h_overrides.append((key, f"{start}-{end}"))

        # Сортируем по ключу, чтобы порядок был h1, h2, h3, h4
        h_overrides.sort(key=lambda x: ("h1", "h2", "h3", "h4").index(x[0]))
        h1, h2, h3, h4 = (v for _, v in h_overrides)

    # ── I1 — CPS tag-формат <r N> (AWG 2.0: 24-32; 3.1: 32-256) ─────────
    # v5.1: раньше генерировался голый hex (AWG 1.5). Теперь — CPS tag-формат
    # <r N>, как в awgs_presets_generate() для i1_mode='random'. Голый hex
    # ломает некоторых клиентов AWG 2.0 (Keenetic, amneziawg-go).
    # Override принимается as-is (через _is_valid_cps_or_legacy_hex проходит
    # и CPS, и legacy hex).
    # AWG 3.1: N 32-256 (GenerateObfuscation31).
    if "i1" in overrides and overrides["i1"]:
        i1 = str(overrides["i1"])
    elif is_31:
        i1 = f"<r {random.randint(32, 256)}>"
    else:
        i1_size = random.randint(24, 32)
        i1 = f"<r {i1_size}>"

    # ── I2-I5 — по умолчанию пустые, но принимают override ────────────────
    i2 = str(overrides["i2"]) if "i2" in overrides and overrides["i2"] else ""
    i3 = str(overrides["i3"]) if "i3" in overrides and overrides["i3"] else ""
    i4 = str(overrides["i4"]) if "i4" in overrides and overrides["i4"] else ""
    i5 = str(overrides["i5"]) if "i5" in overrides and overrides["i5"] else ""

    params = {
        "jc":   jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1":   s1, "s2": s2, "s3": s3, "s4": s4,
        "h1":   h1, "h2": h2, "h3": h3, "h4": h4,
        "i1":   i1, "i2": i2, "i3": i3, "i4": i4, "i5": i5,
    }

    # AWG 3.1: добавляем 9 транспортных параметров (HeaderProtectionKey и т.д.).
    # Overrides с 3.1-ключами уважаются (awg31_merge_into_params заполняет
    # только отсутствующие/пустые).
    if is_31:
        extra_overrides = {k: overrides[k] for k in overrides
                           if k in ("header_protection_key", "content_padding_addition",
                                    "rekey_after_time", "rekey_timeout",
                                    "reject_after_time", "keepalive_timeout",
                                    "max_handshake_attempts", "random_trailers",
                                    "disable_cookies") and overrides[k]}
        params = awg31_merge_into_params(params, extra_overrides or None)

    return params
