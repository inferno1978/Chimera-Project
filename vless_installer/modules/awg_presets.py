"""
vless_installer/modules/awg_presets.py
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
    Перенесено из validate_jc_value/validate_junk_size в bivlked.
    """
    from .awg_constants import (
        AWGS_JC_MIN, AWGS_JC_MAX, AWGS_JMIN_MAX, AWGS_JMAX_MAX,
        AWGS_S3_MAX, AWGS_S4_MAX,
    )

    jc = params.get("jc", 0)
    if not isinstance(jc, int) or jc < AWGS_JC_MIN or jc > AWGS_JC_MAX:
        return False, f"Jc={jc} вне диапазона ({AWGS_JC_MIN}-{AWGS_JC_MAX})"

    jmin = params.get("jmin", 0)
    if not isinstance(jmin, int) or jmin < 0 or jmin > AWGS_JMIN_MAX:
        return False, f"Jmin={jmin} вне диапазона (0-{AWGS_JMIN_MAX})"

    jmax = params.get("jmax", 0)
    if not isinstance(jmax, int) or jmax < 0 or jmax > AWGS_JMAX_MAX:
        return False, f"Jmax={jmax} вне диапазона (0-{AWGS_JMAX_MAX})"

    if jmax < jmin:
        return False, f"Jmax ({jmax}) меньше Jmin ({jmin})"

    s3 = params.get("s3", 0)
    if not isinstance(s3, int) or s3 < 0 or s3 > AWGS_S3_MAX:
        return False, f"S3={s3} вне диапазона (0-{AWGS_S3_MAX})"

    s4 = params.get("s4", 0)
    if not isinstance(s4, int) or s4 < 0 or s4 > AWGS_S4_MAX:
        return False, f"S4={s4} вне диапазона (0-{AWGS_S4_MAX})"

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
