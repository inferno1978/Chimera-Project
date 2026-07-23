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
  i1_mode           — "random" | "absent" | "binary" (см. bivlked)
                     random: случайный I1
                     absent: не указывать I1
                     binary: использовать I1 как binary blob
"""
from __future__ import annotations

import random
from typing import Optional


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


def awgs_presets_generate(name: str = "default") -> dict:
    """
    Генерирует конкретные значения параметров обфускации по пресету.
    Возвращает dict с ключами: jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4, i1..i5
    """
    preset = AWGS_CARRIER_PRESETS.get(name)
    if not preset:
        raise ValueError(f"Неизвестный пресет: '{name}'. "
                         f"Допустимые: {', '.join(AWGS_CARRIER_PRESETS.keys())}")

    # Jc — случайное целое в диапазоне
    jc = random.randint(preset["jc_min"], preset["jc_max"])

    # Jmin — случайное целое в диапазоне
    jmin = random.randint(preset["jmin_min"], preset["jmin_max"])

    # Jmax = Jmin + delta (delta в диапазоне)
    jmax_delta = random.randint(preset["jmax_delta_min"], preset["jmax_delta_max"])
    jmax = jmin + jmax_delta

    # S1-S4 — по умолчанию 0 (как в bivlked)
    s1, s2, s3, s4 = 0, 0, 0, 0

    # H1-H4 — magic headers (как в bivlked default)
    h1, h2, h3, h4 = 1, 2, 3, 4

    # I1 — зависит от i1_mode
    i1_mode = preset["i1_mode"]
    if i1_mode == "random":
        # Случайный I1 (24-32 байта, hex)
        i1_len = random.randint(24, 32)
        i1 = "".join(random.choices("0123456789abcdef", k=i1_len * 2))
    elif i1_mode == "binary":
        # Binary blob (для T-Mobile US — короткий фиксированный)
        i1 = "".join(random.choices("0123456789abcdef", k=16))
    else:  # absent
        i1 = ""

    # I2-I5 — пустые (опциональные)
    i2 = i3 = i4 = i5 = ""

    return {
        "jc":   jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1":   s1, "s2": s2, "s3": s3, "s4": s4,
        "h1":   h1, "h2": h2, "h3": h3, "h4": h4,
        "i1":   i1, "i2": i2, "i3": i3, "i4": i4, "i5": i5,
    }


def awgs_presets_validate_params(params: dict) -> tuple[bool, str]:
    """
    Валидирует параметры обфускации.
    Возвращает (ok, error_message).
    Перенесено из validate_jc_value/validate_junk_size в bivlked + расширено
    для S1/S2 (нет явного max в bivlked, используем 1280 как для Jmin/Jmax)
    и H1-H4 (0-255, magic header byte).
    """
    from .awg_constants import (
        AWGS_JC_MIN, AWGS_JC_MAX, AWGS_JMIN_MAX, AWGS_JMAX_MAX,
        AWGS_S3_MAX, AWGS_S4_MAX,
    )

    # Jc: 1-128
    jc = params.get("jc", 0)
    if not isinstance(jc, int) or jc < AWGS_JC_MIN or jc > AWGS_JC_MAX:
        return False, f"Jc={jc} вне диапазона ({AWGS_JC_MIN}-{AWGS_JC_MAX})"

    # Jmin: 0-1280
    jmin = params.get("jmin", 0)
    if not isinstance(jmin, int) or jmin < 0 or jmin > AWGS_JMIN_MAX:
        return False, f"Jmin={jmin} вне диапазона (0-{AWGS_JMIN_MAX})"

    # Jmax: 0-1280, >= Jmin
    jmax = params.get("jmax", 0)
    if not isinstance(jmax, int) or jmax < 0 or jmax > AWGS_JMAX_MAX:
        return False, f"Jmax={jmax} вне диапазона (0-{AWGS_JMAX_MAX})"
    if jmax < jmin:
        return False, f"Jmax ({jmax}) меньше Jmin ({jmin})"

    # S1, S2: 0-1280 (junk size, как Jmin/Jmax)
    for key in ("s1", "s2"):
        v = params.get(key, 0)
        if not isinstance(v, int) or v < 0 or v > AWGS_JMIN_MAX:
            return False, f"{key.upper()}={v} вне диапазона (0-{AWGS_JMIN_MAX})"

    # S3: 0-64
    s3 = params.get("s3", 0)
    if not isinstance(s3, int) or s3 < 0 or s3 > AWGS_S3_MAX:
        return False, f"S3={s3} вне диапазона (0-{AWGS_S3_MAX})"

    # S4: 0-32
    s4 = params.get("s4", 0)
    if not isinstance(s4, int) or s4 < 0 or s4 > AWGS_S4_MAX:
        return False, f"S4={s4} вне диапазона (0-{AWGS_S4_MAX})"

    # H1-H4: magic headers. По официальной документации AmneziaWG
    # (docs.amnezia.org) безопасный верхний предел — INT32_MAX (2147483647).
    # amneziawg-windows-client может подсвечивать значения выше как invalid.
    # Можно как одиночное число, так и диапазон "N-M" (но в проекте сейчас
    # всегда int — диапазоны не поддерживаются).
    # v5.0.0: расширено с 0-255 до 0-INT32_MAX — раньше было слишком узко,
    # не позволяло awgs_generate_full_manual_params() генерировать
    # уникальные H1-H4 в полном диапазоне (что нужно для устойчивости к DPI).
    _H_MAX = 2147483647  # INT32_MAX
    for key in ("h1", "h2", "h3", "h4"):
        v = params.get(key, 0)
        if not isinstance(v, int) or v < 0 or v > _H_MAX:
            return False, f"{key.upper()}={v} вне диапазона (0-{_H_MAX})"

    # I1-I5: опциональные hex-строки (если не пустые — проверяем что hex)
    for key in ("i1", "i2", "i3", "i4", "i5"):
        v = params.get(key, "")
        if v and not isinstance(v, str):
            return False, f"{key.upper()} должен быть строкой"
        if v and not all(c in "0123456789abcdefABCDEF" for c in v):
            return False, f"{key.upper()} содержит не-hex символы"

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
#  ПОЛНАЯ РУЧНАЯ ГЕНЕРАЦИЯ (v5.0.0) — отдельный путь, не связан с пресетами
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


def awgs_generate_full_manual_params(overrides: dict | None = None) -> dict:
    """Генерирует ПОЛНЫЙ набор параметров AWG 2.0 (все 16: Jc/Jmin/Jmax/
    S1-S4/H1-H4/I1-I5) со случайными значениями в рекомендованных
    диапазонах по умолчанию.

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

    I1 — hex-строка 48-64 символа (как i1_mode=random в awgs_presets_
    generate). I2-I5 — по умолчанию пустые, но принимают override,
    если пользователь явно захочет задать.

    Правило совместимости S1 + 56 != S2 проверяется при генерации —
    если случайно совпало (padded init и padded response совпадут по
    размеру, что выдаёт VPN), S2 перегенерируется.

    Возвращает dict с 16 ключами: jc/jmin/jmax/s1-s4/h1-h4/i1-i5.
    Формат совпадает с awgs_presets_generate() — можно передавать
    в awgs_presets_validate_params() и в awgs_build_server_conf().
    """
    overrides = overrides or {}
    r = _FULL_MANUAL_RANGES

    # ── Jc ────────────────────────────────────────────────────────────────
    if "jc" in overrides:
        jc = int(overrides["jc"])
    else:
        jc = random.randint(r["jc"][0], r["jc"][1])

    # ── Jmin/Jmax ─────────────────────────────────────────────────────────
    if "jmin" in overrides:
        jmin = int(overrides["jmin"])
    else:
        jmin = random.randint(r["jmin"][0], r["jmin"][1])

    if "jmax" in overrides:
        jmax = int(overrides["jmax"])
    else:
        jmax_delta = random.randint(r["jmax_delta"][0], r["jmax_delta"][1])
        jmax = jmin + jmax_delta
    # Safety: Jmax должен быть >= Jmin
    if jmax < jmin:
        jmax = jmin

    # ── S1, S2 (с правилом S1 + 56 != S2) ─────────────────────────────────
    if "s1" in overrides:
        s1 = int(overrides["s1"])
    else:
        s1 = random.randint(r["s1"][0], r["s1"][1])

    if "s2" in overrides:
        s2 = int(overrides["s2"])
    else:
        # Перегенерируем S2 если S1 + 56 == S2 (паттерн, выдающий VPN)
        # Делаем до 10 попыток, потом принудительно сдвигаем.
        s2 = random.randint(r["s2"][0], r["s2"][1])
        for _attempt in range(10):
            if s1 + 56 != s2:
                break
            s2 = random.randint(r["s2"][0], r["s2"][1])
        else:
            # Все 10 попыток совпали (маловероятно для диапазона 0-32) —
            # принудительно сдвигаем S2 на 1 от S1+56.
            s2 = (s1 + 57) & 0xFFFFFFFF
            if s2 > r["s2"][1]:
                s2 = r["s2"][1] if r["s2"][1] != (s1 + 56) else r["s2"][0]

    # ── S3, S4 ────────────────────────────────────────────────────────────
    if "s3" in overrides:
        s3 = int(overrides["s3"])
    else:
        s3 = random.randint(r["s3"][0], r["s3"][1])

    if "s4" in overrides:
        s4 = int(overrides["s4"])
    else:
        s4 = random.randint(r["s4"][0], r["s4"][1])

    # ── H1-H4 — непересекающиеся случайные значения в 1..INT32_MAX ────────
    # Каждое значение выбирается случайно из всего диапазона 1..2^31-1,
    # с гарантией что все 4 значения различны (DPI не сможет написать
    # универсальное правило для детекции этого проекта).
    used_h = set()
    h_values = []
    # Учёт overrides для H1-H4
    h_overrides = []
    for key in ("h1", "h2", "h3", "h4"):
        if key in overrides:
            hv = int(overrides[key])
            h_overrides.append((key, hv))
            used_h.add(hv)
    # Заполняем остальные (без override) — случайно, без пересечений
    for key in ("h1", "h2", "h3", "h4"):
        if key in overrides:
            continue
        # Подбираем случайное значение, не пересекающееся с уже использованными
        for _attempt in range(50):
            hv = random.randint(1, _H_UPPER_LIMIT)
            if hv not in used_h:
                break
        else:
            # 50 попыток не хватило (невероятно для INT32_MAX) — берём
            # любое непересекающееся через инкремент
            hv = 1
            while hv in used_h:
                hv += 1
                if hv > _H_UPPER_LIMIT:
                    hv = 1
        used_h.add(hv)
        h_overrides.append((key, hv))
    # Сортируем по ключу, чтобы порядок был h1, h2, h3, h4
    h_overrides.sort(key=lambda x: ("h1", "h2", "h3", "h4").index(x[0]))
    h1, h2, h3, h4 = (v for _, v in h_overrides)

    # ── I1 — hex 48-64 символа (24-32 байта) ──────────────────────────────
    if "i1" in overrides and overrides["i1"]:
        i1 = str(overrides["i1"])
    else:
        i1_len = random.randint(24, 32)
        i1 = "".join(random.choices("0123456789abcdef", k=i1_len * 2))

    # ── I2-I5 — по умолчанию пустые, но принимают override ────────────────
    i2 = str(overrides["i2"]) if "i2" in overrides and overrides["i2"] else ""
    i3 = str(overrides["i3"]) if "i3" in overrides and overrides["i3"] else ""
    i4 = str(overrides["i4"]) if "i4" in overrides and overrides["i4"] else ""
    i5 = str(overrides["i5"]) if "i5" in overrides and overrides["i5"] else ""

    return {
        "jc":   jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1":   s1, "s2": s2, "s3": s3, "s4": s4,
        "h1":   h1, "h2": h2, "h3": h3, "h4": h4,
        "i1":   i1, "i2": i2, "i3": i3, "i4": i4, "i5": i5,
    }
