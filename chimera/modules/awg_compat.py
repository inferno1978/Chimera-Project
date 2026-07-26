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
а не жёстко "всегда" или "никогда".

v5.2.1 (критический фикс): проверка через `awg-quick strip` НЕ РАБОТАЛА
— strip это текстовый фильтр, не валидирует содержимое [Interface] за
пределами своих собственных директив (Address/DNS/MTU/Table и т.д.),
а просто пропускает остальное насквозь без проверки. Реальная валидация
(та, что рожает 'Line unrecognized: I2=') происходит внутри `awg setconf`,
вызываемого при настоящем `up` — strip до этой стадии не доходит вообще.
Подтверждено на сервере ArkadiaGamingHub: strip давал False Positive
100% времени. Заменен на реальный `awg setconf` против временного
тестового интерфейса (не awg0! — не трогая реальный работающий интерфейс
пользователя). Результат кэшируется на время процесса.
"""
from __future__ import annotations

import tempfile
import uuid
from pathlib import Path


# ── Кэш результата проверки (на время процесса) ─────────────────────────────
# Не гоняем проверку на каждый apply — она делает subprocess-вызовы
# (ip link add + awg setconf + ip link delete) и tempfile I/O.
# Кэшируем в module-level dict после первого вызова.
_SUPPORTS_I2_I5_CACHE: dict[str, bool] = {}


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def _run_setconf_check(sample_conf: str) -> tuple[bool, str]:
    """Создаёт ВРЕМЕННЫЙ интерфейс с уникальным именем (НЕ awg0!),
    пытается `awg setconf` на нём с тестовым конфигом, удаляет интерфейс.
    Возвращает (success, stderr+stdout).

    В отличие от `awg-quick strip` (текстовый фильтр, не валидирует
    содержимое [Interface] за пределами своих собственных директив —
    Address/DNS/MTU/Table и т.д., а просто пропускает остальное насквозь
    без проверки), `awg setconf` — это РЕАЛЬНЫЙ путь валидации, тот же
    самый, что вызывается при `up`. Это единственный надёжный способ
    проверить, распознаёт ли локальный amneziawg-tools директивы I2-I5 —
    без этого весь механизм детекции бесполезен (подтверждено на реальном
    сервере ArkadiaGamingHub: strip давал False Positive 100% времени).

    Безопасность:
      - Имя тестового интерфейса генерируется через uuid — гарантированно
        не совпадает с AWGS_INTERFACE ("awg0") или любым другим
        существующим интерфейсом.
      - Дополнительная explicit-проверка test_iface != AWGS_INTERFACE —
        защита от случайного повреждения реального интерфейса
        пользователя (вернуть True, не трогать awg0).
      - Интерфейс ВСЕГДА удаляется в finally-блоке, даже при ошибке
        setconf — не оставляем мусор в системе.
      - setconf запускается с tempfile (atomic), tempfile тоже удаляется
        в finally.
      - Исключения из core._run (FileNotFoundError и пр.) ловятся и
        возвращаются как (False, str(e)) — не валит весь процесс.

    sample_conf должен быть в "стриппнутом" формате (как awg-quick strip
    производит): только [Interface] с PrivateKey/ListenPort/Jc.../I1-I5.
    НЕ содержит Address/MTU/DNS/Table/PreUp/PostUp — иначе setconf
    отвергнет его по другой причине (не про I2), и тест даст ложный
    отрицательный результат.
    """
    # Уникальное имя интерфейса — гарантированно не совпадает с awg0
    # (AWGS_INTERFACE). Префикс "awgprobe" для удобства диагностики
    # (если в системе останется мусорный интерфейс, по имени видно
    # откуда он).
    test_iface = f"awgprobe{uuid.uuid4().hex[:8]}"

    core = _core_module()
    from .awg_constants import AWGS_BIN, AWGS_INTERFACE

    # Защита от случайного повреждения реального интерфейса пользователя.
    # uuid гарантирует уникальность, но эта explicit-проверка добавляет
    # второй слой safety — если вдруг AWGS_INTERFACE изменится в будущем
    # на что-то начинающееся с "awgprobe", мы всё равно откажемся.
    if test_iface == AWGS_INTERFACE:
        return (True, "test interface name collision with awg0 — refusing to test")

    # Флаг: был ли интерфейс реально создан (чтобы в finally знать,
    # нужно ли его удалять). Если `ip link add` упал — интерфейса нет,
    # и `ip link delete` вызывать не нужно.
    interface_created = False
    try:
        try:
            # Создаём тестовый интерфейс (без адресов/поднятия — только
            # чтобы было куда применить setconf).
            r_add = core._run(
                ["ip", "link", "add", test_iface, "type", "amneziawg"],
                capture=True, check=False,
            )
            if r_add.returncode != 0:
                # Не удалось создать тестовый интерфейс — DKMS-модуль не
                # загружен, нет CAP_NET_ADMIN, или другая причина. Это НЕ
                # про I2-I5, поэтому safe default True (см. существующую
                # edge case логику в awgs_supports_i2_i5 — лучше написать
                # все 5 ключей и пусть пользователь обновит amneziawg-tools,
                # чем молча выкинуть I2-I5 и потерять decoy-пакеты на
                # совместимой системе).
                return (True, r_add.stderr or "interface creation failed")
            interface_created = True

            # Пишем sample_conf во tempfile (setconf принимает путь к файлу).
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".conf", delete=False
            ) as tmp:
                tmp.write(sample_conf)
                tmp_path = tmp.name
            try:
                # awg setconf <iface> <file> — РЕАЛЬНЫЙ путь валидации
                # (тот же, что вызывается при `awg-quick up`).
                r = core._run(
                    [AWGS_BIN, "setconf", test_iface, tmp_path],
                    capture=True, check=False,
                )
                return (r.returncode == 0, (r.stderr or "") + (r.stdout or ""))
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        except Exception as e:
            # Исключение из core._run (FileNotFoundError если ip/awg нет
            # в PATH, и пр.) — возвращаем как (False, str(e)). Не валит
            # весь процесс, позволяет awgs_supports_i2_i5 применить
            # safe-default логику.
            return (False, str(e))
    finally:
        # Обязательно удаляем тестовый интерфейс, даже при ошибке.
        # Не вызываем delete если интерфейс не был создан — это
        # микро-оптимизация, но и semantic-correctness (не пытаемся
        # удалить то, чего нет).
        # Заворачиваем в try/except чтобы не маскировать оригинальную
        # ошибку — если delete тоже упадёт, логируем но не пробрасываем.
        if interface_created:
            try:
                core._run(["ip", "link", "delete", "dev", test_iface],
                          capture=True, check=False)
            except Exception:
                # Не маскируем оригинальную ошибку. Интерфейс может
                # остаться в системе, но это лучше чем уронить процесс.
                # Логируем для диагностики.
                try:
                    core.log_to_file(
                        "WARN",
                        f"_run_setconf_check: failed to delete test "
                        f"interface {test_iface} — may need manual cleanup"
                    )
                except Exception:
                    pass


def awgs_supports_i2_i5(force_refresh: bool = False) -> bool:
    """Проверяет, поддерживает ли локальный awg-quick директивы I2-I5.

    Возвращает True если локальный amneziawg-tools понимает директивы
    I2/I3/I4/I5 в .conf (это AWG 2.0-era сборки). Возвращает False если
    это старая сборка (AWG 1.5-эра), которая падает с
    'Line unrecognized: I2=' при виде этих директив.

    Способ проверки (v5.2.1 — КРИТИЧЕСКИ ИЗМЕНЁН):
      Создаём ВРЕМЕННЫЙ интерфейс с уникальным именем (НЕ awg0!),
      применяем к нему тестовый .conf через `awg setconf`, удаляем
      интерфейс. setconf — это РЕАЛЬНЫЙ путь валидации, тот же, что
      вызывается при `awg-quick up`. Если setconf падает с ошибкой про
      I2/I3/I4/I5 — поддержка отсутствует.

      v5.2 использовал `awg-quick strip` — но strip это текстовый
      фильтр, не валидирует содержимое [Interface] за пределами своих
      собственных директив. Подтверждено на сервере ArkadiaGamingHub:
      strip давал False Positive 100% времени (возвращал True даже для
      старых amneziawg-tools, которые реально не поддерживают I2-I5).
      v5.2.1 — заменён на setconf, единственный надёжный способ.

    Результат кэшируется на время процесса (не гоняем проверку на
    каждый apply). Используйте force_refresh=True для принудительной
    перепроверки (нужно в тестах).

    Edge cases:
      - awg-quick / awg не установлен в системе (тестовое окружение,
        свежий сервер до установки DKMS) — возвращаем True
        (безопасный default: лучше написать все 5 ключей и пусть
        пользователь обновит amneziawg-tools, чем молча выкинуть
        I2-I5 и потерять decoy-пакеты на совместимой системе).
      - `ip link add` падает (DKMS-модуль не загружен, нет прав) —
        тоже возвращаем True по той же причине.
      - setconf падает по НЕ I2-I5 причине (например, privkey
        невалидный, или awg нет в PATH) — возвращаем True (safe
        default), чтобы не выкинуть I2-I5 из-за ложного срабатывания.
      - На тестах mock'ается через _SUPPORTS_I2_I5_CACHE directly
        или через patch _run_setconf_check.
    """
    if not force_refresh and "result" in _SUPPORTS_I2_I5_CACHE:
        return _SUPPORTS_I2_I5_CACHE["result"]

    # Минимальный тестовый конфиг в "стриппнутом" формате (как awg-quick
    # strip производит): только [Interface] с PrivateKey/ListenPort/
    # Jc.../I1-I5. НЕ содержит Address/MTU/DNS/Table/PreUp/PostUp —
    # иначе setconf отвергнет его по другой причине (не про I2), и тест
    # даст ложный отрицательный результат.
    #
    # Приватный ключ — заглушка (32 байта base64, all-zeros валиден как
    # Curve25519 identity element — amneziawg-tools принимает любой
    # 32-байтный base64).
    # ListenPort = 0 — kernel присваивает ephemeral port, не конфликтует
    # с реальным awg0 (который обычно на 51820).
    # I1 — CPS tag (валидный для AWG 2.0), I2-I5 — пустые. Старый
    # amneziawg-tools упадёт в setconf уже на парсинге "I2 = " с
    # 'Line unrecognized: I2='. Современный — примет.
    sample_conf = (
        "[Interface]\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "ListenPort = 0\n"
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

    ok, output = _run_setconf_check(sample_conf)

    if not ok:
        # Проверяем, что ошибка действительно про I2-I5, а не про что-то
        # другое (например, privkey невалидный, или awg нет в PATH, или
        # `ip link add` упал).
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
                f"awgs_supports_i2_i5: awg setconf failed for "
                f"non-I2 reason, defaulting to True. stderr: {output[:300]}"
            )
        except Exception:
            pass
        _SUPPORTS_I2_I5_CACHE["result"] = True
        return True

    # setconf прошёл — значит I2-I5 поддерживаются
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
