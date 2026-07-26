"""
chimera/modules/awg_compat.py
───────────────────────────────────────────────────────────────────────────────
Определение возможностей локально установленного amneziawg-tools.

v5.2: коммит 3e1fa70 ("всегда писать I1-I5 в .conf") ломает совместимость
со старыми сборками amneziawg-tools (AWG 1.5-эра), которые поддерживают
только I1 и вообще не знают директиву I2 — падают с
'Line unrecognized: I2=' / "Configuration parsing error", сервис
awg-quick@awg0 не поднимается ВООБЩЕ (не просто "туннель не идёт",
а полный отказ старта).

Подтверждено реальным логом пользователя (journalctl -u awg-quick@awg0),
сервер ArkadiaGamingHub, установка через Chimera.

КОНФЛИКТ ТРЕБОВАНИЙ:
  - Строгие парсеры (Keenetic native AWG 2.0) требуют ВСЕ 5 ключей
    I1-I5 присутствующими, даже пустыми (это и было причиной 3e1fa70).
  - Старые сборки amneziawg-tools вообще не знают про I2-I5 как
    директивы — видят такую строку и ПАДАЮТ с ошибкой парсинга.

Решение: определять возможности локального awg-quick ПЕРЕД записью .conf,
а не жёстко "всегда" или "никогда". Проверка через `awg-quick strip`
(парсит конфиг БЕЗ поднятия интерфейса — безопаснее чем реальный up/down).
Результат кэшируется на время процесса.
"""
from __future__ import annotations

import tempfile
from pathlib import Path


# ── Кэш результата проверки (на время процесса) ─────────────────────────────
# Не гоняем проверку на каждый apply — она делает subprocess-вызов и
# tempfile I/O. Кэшируем в module-level dict после первого вызова.
_SUPPORTS_I2_I5_CACHE: dict[str, bool] = {}


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def _run_strip_check(quick_bin: str, sample_conf: str) -> tuple[bool, str]:
    """Запускает `awg-quick strip` на sample_conf и возвращает
    (success, stderr).

    strip — это режим парсинга конфига без поднятия интерфейса:
    awg-quick strip <conf> читает конфиг, парсит его, и печатает
    нормализованный wireguard-конфиг в stdout. Если конфиг невалиден
    (например содержит неизвестную директиву I2 в старом amneziawg-tools),
    strip падает с "Line unrecognized" в stderr и ненулевым returncode.

    Это безопасный способ проверить, понимает ли локальный awg-quick
    директивы I2-I5 — без реального up/down интерфейса.
    """
    core = _core_module()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    ) as tmp:
        tmp.write(sample_conf)
        tmp_path = tmp.name
    try:
        r = core._run([quick_bin, "strip", tmp_path],
                      capture=True, check=False)
        return (r.returncode == 0, (r.stderr or "") + (r.stdout or ""))
    except Exception as e:
        return (False, str(e))
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def awgs_supports_i2_i5(force_refresh: bool = False) -> bool:
    """Проверяет, поддерживает ли локальный awg-quick директивы I2-I5.

    Возвращает True если локальный amneziawg-tools понимает директивы
    I2/I3/I4/I5 в .conf (это AWG 2.0-era сборки). Возвращает False если
    это старая сборка (AWG 1.5-эра), которая падает с
    'Line unrecognized: I2=' при виде этих директив.

    Способ проверки — САМЫЙ надёжный, не гадать по номеру версии в
    строке (версии в разных дистрибутивах/форках именуются по-разному):
    собираем МИНИМАЛЬНЫЙ тестовый .conf с непустым I1 и пустым I2,
    прогоняем через `awg-quick strip` (парсит конфиг БЕЗ поднятия
    интерфейса — безопаснее чем реальный up/down). Если strip падает
    с ошибкой про I2/I3/I4/I5 — поддержка отсутствует.

    Результат кэшируется на время процесса (не гоняем проверку на
    каждый apply). Используйте force_refresh=True для принудительной
    перепроверки (нужно в тестах).

    Edge cases:
      - awg-quick не установлен в системе (тестовое окружение,
        свежий сервер до установки DKMS) — возвращаем True
        (безопасный default: лучше написать все 5 ключей и пусть
        пользователь обновит amneziawg-tools, чем молча выкинуть
        I2-I5 и потерять decoy-пакеты на совместимой системе).
      - awg-quick strip вообще не работает (повреждённая установка) —
        тоже возвращаем True по той же причине.
      - На тестах mock'ается через _SUPPORTS_I2_I5_CACHE directly
        или через patch _run_strip_check.
    """
    if not force_refresh and "result" in _SUPPORTS_I2_I5_CACHE:
        return _SUPPORTS_I2_I5_CACHE["result"]

    from .awg_constants import AWGS_QUICK_BIN

    # Минимальный тестовый конфиг. I1 — CPS tag (валидный для AWG 2.0),
    # I2 — пустая строка. Старый amneziawg-tools упадёт уже на парсинге
    # строки "I2 = " с 'Line unrecognized: I2='. Современный —
    # примет и вернёт strip'нутый конфиг.
    #
    # Приватный ключ — заглушка (wg-quick strip его парсит, но не
    # использует для реальных crypto-операций в strip-режиме).
    # 32 байта base64 = 44 символа.
    sample_conf = (
        "[Interface]\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 10.66.66.1/24\n"
        "ListenPort = 51820\n"
        "Jc = 3\n"
        "Jmin = 40\n"
        "Jmax = 70\n"
        "S1 = 0\n"
        "S2 = 0\n"
        "S3 = 0\n"
        "S4 = 0\n"
        "H1 = 1\n"
        "H2 = 2\n"
        "H3 = 3\n"
        "H4 = 4\n"
        "I1 = <r 24>\n"
        "I2 = \n"
        "I3 = \n"
        "I4 = \n"
        "I5 = \n"
    )

    ok, output = _run_strip_check(AWGS_QUICK_BIN, sample_conf)

    if not ok:
        # Проверяем, что ошибка действительно про I2-I5, а не про что-то
        # другое (например, privkey невалидный, или awg-quick нет в PATH).
        # Если ошибка НЕ про I2-I5 — лучше вернуть True (default safe),
        # чтобы не выкинуть I2-I5 из-за ложного срабатывания.
        output_lower = output.lower()
        if any(token in output_lower for token in (
            "i2", "i3", "i4", "i5",
            "line unrecognized", "configuration parsing error",
        )):
            # Точно не поддерживает I2-I5
            _SUPPORTS_I2_I5_CACHE["result"] = False
            return False
        # Ошибка по другой причине — лучше вернём True (safe default),
        # чтобы не выкинуть I2-I5 из-за ложного срабатывания. Логируем
        # для диагностики.
        try:
            core = _core_module()
            core.log_to_file(
                "WARN",
                f"awgs_supports_i2_i5: awg-quick strip failed for "
                f"non-I2 reason, defaulting to True. stderr: {output[:300]}"
            )
        except Exception:
            pass
        _SUPPORTS_I2_I5_CACHE["result"] = True
        return True

    # strip прошёл — значит I2-I5 поддерживаются
    _SUPPORTS_I2_I5_CACHE["result"] = True
    return True


def _reset_supports_cache() -> None:
    """Сбрасывает кэш awgs_supports_i2_i5(). Для тестов."""
    _SUPPORTS_I2_I5_CACHE.clear()


def _set_supports_cache(value: bool) -> None:
    """Принудительно устанавливает кэш awgs_supports_i2_i5() в value.
    Для тестов — позволяет mock'ать результат без реального subprocess."""
    _SUPPORTS_I2_I5_CACHE["result"] = value


# ── Сообщения для пользователя ───────────────────────────────────────────────

_OLD_AWG_TOOLS_WARN_SHOWN: bool = False


def awgs_warn_old_tools_once() -> None:
    """Показывает пользователю warn() про старую версию amneziawg-tools
    ОДИН раз за процесс (не спамим на каждый apply).

    Вызывается писателями конфига, когда awgs_supports_i2_i5() == False.
    """
    global _OLD_AWG_TOOLS_WARN_SHOWN
    if _OLD_AWG_TOOLS_WARN_SHOWN:
        return
    _OLD_AWG_TOOLS_WARN_SHOWN = True
    try:
        core = _core_module()
        core.warn(
            "Обнаружена старая версия amneziawg-tools без поддержки I2-I5 — "
            "эти decoy-пакеты недоступны на этом сервере (конфиг пишется "
            "БЕЗ директив I2-I5 для совместимости). Для полной поддержки "
            "AWG 2.0 обновите amneziawg-tools: "
            "apt update && apt install --only-upgrade amneziawg-tools"
        )
    except Exception:
        pass


def _reset_old_tools_warn_flag() -> None:
    """Сбрасывает флаг 'показан ли warn про старый awg-tools'. Для тестов."""
    global _OLD_AWG_TOOLS_WARN_SHOWN
    _OLD_AWG_TOOLS_WARN_SHOWN = False
