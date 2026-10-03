"""
chimera/modules/awg_apply.py
───────────────────────────────────────────────────────────────────────────────
Применение конфига awg0.conf к работающему сервису.

Два режима (как в bivlked):
  • syncconf  — без даунтайма (по умолчанию). Использует `awg syncconf` для
                атомарного обновления peer'ов без разрыва соединений.
  • restart   — fallback при kernel panic / нестабильности. Полный рестарт
                awg-quick@awg0.service.

v5.2.2: Самоисцеление при ошибке 'Line unrecognized: I2=' — если apply падает
из-за того, что локальный amneziawg-tools не поддерживает директивы I2-I5
(старая сборка AWG 1.5-эры, которая распознаёт I1 но не I2-I5), конфиг
автоматически переписывается без пустых I2-I5 и apply повторяется. Это
решает проблему для УЖЕ СЛОМАННЫХ установок (как у zvshka на сервере
ArkadiaGamingHub) — срабатывает при ЛЮБОМ действии, включая systemctl
restart, без требования от пользователя запустить конкретное меню.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from .awg_constants import (
    AWGS_BIN, AWGS_QUICK_BIN, AWGS_INTERFACE, AWGS_SERVER_CONF,
    AWGS_APPLY_MODE_SYNCCONF, AWGS_APPLY_MODE_RESTART,
    AWGS_SYNC_TIMEOUT_SEC, AWGS_RESTART_TIMEOUT_SEC,
)


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# Флаг для предотвращения бесконечной рекурсии при самоисцелении.
# _self_heal_i2_i5_incompatibility() вызывает awgs_apply_syncconf() повторно,
# и если та тоже падает, мы не должны снова пытаться самоисцелиться.
_SELF_HEAL_IN_PROGRESS: bool = False


def awgs_apply_syncconf() -> bool:
    """
    Применяет конфиг без даунтайма через `awg syncconf`.
    Возвращает True при успехе.
    """
    core = _core_module()
    # syncconf требует, чтобы конфиг был в специальном формате.
    # Используем `awg-quick strip` для подготовки, затем `awg syncconf`.
    if not AWGS_SERVER_CONF.exists():
        core.log_to_file("ERROR", f"awgs_apply_syncconf: {AWGS_SERVER_CONF} не существует")
        return False

    # Создаём временный файл со strip'нутым конфигом
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # strip — убирает комментарии и форматирует для syncconf
        r = core._run([AWGS_QUICK_BIN, "strip", str(AWGS_SERVER_CONF)],
                      capture=True, check=False)
        if r.returncode != 0:
            core.log_to_file("ERROR", f"awg syncconf strip: {r.stderr}")
            return False
        Path(tmp_path).write_text(r.stdout)

        # syncconf — атомарное обновление
        r = core._run(
            [AWGS_BIN, "syncconf", AWGS_INTERFACE, tmp_path],
            capture=True, check=False,
        )
        if r.returncode != 0:
            core.log_to_file("ERROR", f"awg syncconf: {r.stderr}")
            return False
        core.log_to_file("INFO", "awgs_apply: syncconf OK")
        return True
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_apply_syncconf: {e}")
        return False
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def awgs_apply_restart() -> bool:
    """
    Полный рестарт awg-quick@awg0.service.
    Используется как fallback при kernel panic или нестабильности syncconf.
    """
    core = _core_module()
    from .awg_constants import AWGS_SYSTEMD_AWG_QUICK
    r = core._run(["systemctl", "restart", AWGS_SYSTEMD_AWG_QUICK],
                  capture=True, check=False)
    if r.returncode != 0:
        core.log_to_file("ERROR", f"awgs_apply_restart: {r.stderr}")
        return False
    core.log_to_file("INFO", "awgs_apply: restart OK")
    return True


def _extract_apply_failure_stderr() -> str:
    """Извлекает stderr от awg setconf на тестовом интерфейсе, используя
    РЕАЛЬНЫЙ конфиг сервера (stripped через awg-quick strip).

    v5.2.2: Заменяет извлечение stderr через `awg-quick strip` (которое НЕ
    работало — strip это текстовый фильтр, не валидирует I2, всегда
    возвращает 0). Новый механизм:

      1. Запускаем `awg-quick strip` на реальном конфиге — получаем
         stripped-формат (без Address/MTU/DNS/Table), именно то, что
         awg-quick передаёт в awg setconf при реальном up.
      2. Запускаем `awg setconf` на ВРЕМЕННОМ тестовом интерфейсе
         (awgprobe<uuid>, не awg0!) с этим stripped конфигом.
      3. Если amneziawg-tools не поддерживает I2-I5, setconf падает с
         'Line unrecognized: I2=' — это и есть точная причина сбоя
         awgs_apply_syncconf.

    Безопасность: тестовый интерфейс создаётся с уникальным именем (uuid),
    гарантированно не awg0. Удаляется в finally. См. awg_compat._run_setconf_check.
    """
    try:
        from .awg_compat import _run_setconf_check
        core = _core_module()

        if not AWGS_SERVER_CONF.exists():
            return ""

        # Шаг 1: awg-quick strip на реальном конфиге
        r = core._run([AWGS_QUICK_BIN, "strip", str(AWGS_SERVER_CONF)],
                      capture=True, check=False)
        if r.returncode != 0:
            # strip упал — это другая проблема (не I2), возвращаем stderr strip
            return r.stderr or ""

        stripped_conf = r.stdout
        if not stripped_conf:
            return ""

        # Шаг 2: awg setconf на тестовом интерфейсе с stripped конфигом
        ok, output = _run_setconf_check(stripped_conf)
        if not ok:
            return output
        # setconf прошёл — значит конфиг валиден для локального amneziawg-tools.
        # Причина сбоя awgs_apply_syncconf не в I2-I5 (что-то другое).
        return ""
    except Exception:
        return ""


def _is_i2_i5_unrecognized_error(stderr: str) -> bool:
    r"""Проверяет, связана ли ошибка apply с неподдерживаемыми директивами I2-I5.

    Старые amneziawg-tools (AWG 1.5-эра, переходные сборки) распознают I1,
    но НЕ распознают I2-I5 как директивы. При виде `I2 = ` (даже пустого)
    они выдают:
      Line unrecognized: `I2='
      Configuration parsing error

    Обратите внимание: ошибка `Line unrecognized: \`I2='` — это `I2=` БЕЗ
    значения. Парсер не знает КЛЮЧ I2 вообще (не то что не принимает пустое
    значение). Это переходная версия amneziawg-tools, где I1 был добавлен
    раньше, а I2-I5 пришли позже.

    Эта функция проверяет, что ошибка именно про I2-I5 (а не про что-то
    другое, например, невалидный privkey или отсутствие интерфейса).
    """
    if not stderr:
        return False
    stderr_lower = stderr.lower()
    has_line_unrecognized = "line unrecognized" in stderr_lower
    has_parsing_error = "configuration parsing error" in stderr_lower
    # Проверяем наличие I2/I3/I4/I5 в stderr
    has_i2_i5_token = any(t in stderr_lower for t in ("i2", "i3", "i4", "i5"))
    return (has_line_unrecognized or has_parsing_error) and has_i2_i5_token


def _self_heal_i2_i5_incompatibility() -> bool:
    """Самоисцеление: переписывает конфиг без пустых I2-I5 и повторяет apply.

    v5.2.2: Вызывается, когда apply падает с "Line unrecognized: I2=" — это
    означает, что локальный amneziawg-tools не поддерживает директивы I2-I5
    (старая сборка AWG 1.5-эры, переходная версия с I1 но без I2-I5).

    Действия:
      1. Установить кэш awgs_supports_i2_i5() в False, чтобы будущие записи
         не писали пустые I2-I5
      2. Переписать конфиг без пустых I2-I5 (через awg_peer_rebuild_conf)
      3. Повторить apply (awgs_apply_syncconf)
      4. Если повтор успешен, вернуть True

    Это решает проблему для УЖЕ СЛОМАННЫХ установок (как у zvshka на сервере
    ArkadiaGamingHub) — при следующем apply конфиг автоматически перепишется
    в совместимом виде, без требования от пользователя запустить конкретное
    действие (Rotate obfuscation и т.п.). Достаточно просто перезапустить
    сервис — fallback на restart вызовет apply, который самоисцелится.
    """
    core = _core_module()
    try:
        from .awg_compat import (
            _set_supports_cache, _reset_supports_cache, awgs_warn_old_tools_once,
        )
        from .awg_peers import awg_peer_rebuild_conf

        core.warn(
            "Самоисцеление: обнаружена ошибка 'Line unrecognized: I2=' — "
            "локальный amneziawg-tools не поддерживает директивы I2-I5 "
            "(старая сборка AWG 1.5-эры, переходная версия с I1 но без I2-I5). "
            "Конфиг автоматически переписывается без пустых директив I2-I5 "
            "для совместимости."
        )

        # Сбрасываем кэш и устанавливаем в False — будущие записи конфига
        # (через awgs_build_server_conf / awg_peer_rebuild_conf) НЕ будут
        # писать пустые I2-I5.
        _reset_supports_cache()
        _set_supports_cache(False)
        awgs_warn_old_tools_once()

        # Переписываем конфиг без apply (apply будет ниже).
        # awg_peer_rebuild_conf(apply=False) только записывает awg0.conf,
        # не применяет его. Использует awgs_supports_i2_i5() (теперь False)
        # для условной записи I2-I5.
        if not awg_peer_rebuild_conf(apply=False):
            core.warn("Самоисцеление: не удалось переписать конфиг "
                      "(awg_peer_rebuild_conf вернул False)")
            return False

        # Повторяем apply с переписанным конфигом (без пустых I2-I5)
        if awgs_apply_syncconf():
            core.warn(
                "Самоисцеление УСПЕШНО: конфиг переписан без I2-I5, "
                "apply прошёл. Сервис должен работать. Для полной "
                "поддержки AWG 2.0 обновите amneziawg-tools: "
                "apt update && apt install --only-upgrade amneziawg-tools"
            )
            return True

        core.warn("Самоисцеление: повторный apply также не удался — "
                  "проблема не только в I2-I5, требуется ручная диагностика")
        return False
    except Exception as e:
        core.warn(f"Самоисцеление: исключение — {e}")
        return False


def awgs_apply(mode: str = AWGS_APPLY_MODE_SYNCCONF) -> bool:
    """
    Применяет конфиг в указанном режиме.
    При syncconf-failure автоматически fallback на restart.

    v5.2.2: Самоисцеление — если apply падает с "Line unrecognized: I2="
    (старые amneziawg-tools без поддержки I2-I5), конфиг автоматически
    переписывается без пустых I2-I5 и apply повторяется. Это срабатывает
    при ЛЮБОМ действии (включая systemctl restart через fallback), без
    требования от пользователя запустить конкретное меню. Решает проблему
    для УЖЕ СЛОМАННЫХ установок (как у zvshka).

    v5.2: defensive fallback — показываем пользователю ТОЧНУЮ причину из
    stderr в warn(), а не просто общий "syncconf не удался".
    """
    global _SELF_HEAL_IN_PROGRESS
    core = _core_module()
    if mode == AWGS_APPLY_MODE_RESTART:
        return awgs_apply_restart()

    # syncconf (по умолчанию)
    if awgs_apply_syncconf():
        return True

    # v5.2.2: Извлекаем точную причину сбоя через awg setconf на тестовом
    # интерфейсе (не awg0!). awgs_apply_syncconf использует awg syncconf,
    # которая может не выдавать подробный stderr. awg setconf на тестовом
    # интерфейсе с реальным (stripped) конфигом даёт точную причину — ту же
    # ошибку, что и awg-quick up.
    last_stderr = _extract_apply_failure_stderr()

    # v5.2.2: Самоисцеление — если ошибка про I2-I5, переписать конфиг
    # без них и повторить apply. Только если мы ещё не в процессе
    # самоисцеления (защита от рекурсии).
    if (not _SELF_HEAL_IN_PROGRESS
            and _is_i2_i5_unrecognized_error(last_stderr)):
        _SELF_HEAL_IN_PROGRESS = True
        try:
            if _self_heal_i2_i5_incompatibility():
                return True
        finally:
            _SELF_HEAL_IN_PROGRESS = False

    # v5.5 (AWG 3.1): ошибка про 3.1-директиву (Line unrecognized:
    # HeaderProtectionKey= и т.п.) — это НЕ лечится self-heal по I2-I5:
    # инструменты физически не знают директивы 3.1. Даём точную подсказку
    # и НЕ пытаемся молча деградировать (state обещает 3.1) — fallback
    # на restart тоже покажет ту же ошибку, но конфиг останется на диске.
    if not _SELF_HEAL_IN_PROGRESS:
        try:
            from .awg_compat import awg_is_31_directive_error
            if awg_is_31_directive_error(last_stderr):
                core.warn(
                    "Применение конфига НЕ удалось: локальный amneziawg-tools "
                    "не поддерживает директивы AWG 3.1 (HeaderProtectionKey, "
                    "ContentPaddingAddition, Rekey*, RandomTrailers, "
                    "DisableCookies). Конфиг сохранён на диске; туннель "
                    "продолжает работать на предыдущих параметрах.\n"
                    "Для работы AWG 3.1 обновите инструменты на 3.1-сборку:\n"
                    "  apt update && apt install --only-upgrade amneziawg-tools amneziawg-dkms\n"
                    "(PPA amnezia/ppa; на fresh-установках — amneziawg-tools "
                    "1.1+ / ядро-модуль 3.1-ветки)"
                )
                return False
        except Exception:
            pass

    # Defensive stderr fallback (как в v5.2, но с правильным извлечением stderr)
    if last_stderr:
        snippet = last_stderr[:300]
        if len(last_stderr) > 300:
            snippet += "..."
        core.warn(
            f"Применение конфига НЕ удалось — "
            f"точная причина из stderr:\n  {snippet}\n"
            f"---\n"
            f"Если ошибка про I2/I3/I4/I5 ('Line unrecognized') — установлена "
            f"старая версия amneziawg-tools без поддержки AWG 2.0. "
            f"Обновите: apt update && apt install --only-upgrade amneziawg-tools."
        )
    else:
        core.warn("syncconf не удался — fallback на restart (кратковременный разрыв)")
    return awgs_apply_restart()


def awgs_service_status() -> dict:
    """Возвращает статус awg-quick@awg0.service."""
    core = _core_module()
    from .awg_constants import AWGS_SYSTEMD_AWG_QUICK
    r = core._run(["systemctl", "is-active", AWGS_SYSTEMD_AWG_QUICK],
                  capture=True, check=False)
    active = r.stdout.strip() == "active"
    r2 = core._run(["systemctl", "is-enabled", AWGS_SYSTEMD_AWG_QUICK],
                   capture=True, check=False)
    enabled = r2.stdout.strip() == "enabled"
    return {
        "active":  active,
        "enabled": enabled,
        "raw":     r.stdout.strip(),
    }


def awgs_show_handshakes() -> str:
    """Возвращает вывод `awg show` (peers + handshakes + transfer)."""
    core = _core_module()
    r = core._run([AWGS_BIN, "show", AWGS_INTERFACE],
                  capture=True, check=False)
    return r.stdout if r.returncode == 0 else ""


def awgs_show_dump() -> list:
    """
    Возвращает `awg show all dump` — машиночитаемый формат.
    Первая строка — interface, остальные — peers.
    """
    core = _core_module()
    r = core._run([AWGS_BIN, "show", "all", "dump"],
                  capture=True, check=False)
    if r.returncode != 0:
        return []
    return [line for line in r.stdout.splitlines() if line.strip()]
