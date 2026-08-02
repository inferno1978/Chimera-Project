#!/usr/bin/env python3
"""
tests/test_cron_subprocess_integration.py
───────────────────────────────────────────────────────────────────────────────
ИНТЕГРАЦИОННЫЕ тесты cron-команд, которые РЕАЛЬНО запускают сгенерированные
wrapper-скрипты через subprocess.run() — с рабочей директорией, отличной
от директории проекта (как cron делает в реальности).

Контекст (v5.1): bare ``python3 -c "from chimera.modules..."`` в cron НЕ
работает — cron запускается с произвольной cwd и без PYTHONPATH, поэтому
``from chimera...`` падает с ``ModuleNotFoundError: No module named
'chimera'``. Реальные трейсбеки с сервера пользователя zvshka подтвердили,
что фичи автоудаления истёкших AWG-клиентов и проверки лимитов Telemt
НИКОГДА не срабатывали с момента их появления — несмотря на все зелёные
юнит-тесты (тесты мокали вызов функции напрямую, не реальный запуск через
``python3 -c`` в чужом рабочем окружении).

Этот файл — единственное место в tests/, где проверяется РЕАЛЬНЫЙ запуск
cron-команды через subprocess, с cwd != проектной директории. Любой
будущий cron-генератор с паттерном ``python3 -c "from chimera..."`` БЕЗ
PYTHONPATH будет пойман именно здесь.

Покрывает:
  1. AWG expiry cron (awgs_setup_expires_cron → awgs_expires_check)
  2. Telemt limits cron (mtproto_stats.setup_iptables_accounting →
     mtproto_check_limits)
  3. AWG cascade ru.zone cron (_awgs_cascade_setup_cron →
     awgs_cascade_update_ru_zone) — бонус, тот же класс бага

Для каждого:
  - Генерируем wrapper-скрипт через тестируемую функцию
  - Запускаем его через subprocess.run() с cwd=tmpdir
  - Проверяем ОТСУТСТВИЕ "ModuleNotFoundError" и "No module named
    'chimera'" в stderr (критическая регрессия — фактический баг)
  - Если returncode != 0 — проверяем что ошибка НЕ import-связанная
    (env-специфичные ошибки типа PermissionError на /var/... допустимы,
    они не связаны с фиксируемым багом)

Дополнительно: positive-control тест, который запускает СТАРЫЙ ломанный
паттерн (bare ``python3 -c "from chimera..."`` без PYTHONPATH с cwd=/tmp)
и проверяет, что он ДЕЙСТВИТЕЛЬНО падает с ModuleNotFoundError. Это
гарантирует, что наш тест реально ловит этот класс бага (а не просто
случайно проходит).
"""
from __future__ import annotations

import os
import random
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core в sys.modules (как делают другие тесты)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


# ────────────────────────────────────────────────────────────────────────────
#  Helper: проверка отсутствия ModuleNotFoundError в выводе subprocess
# ────────────────────────────────────────────────────────────────────────────

_MODULE_NOT_FOUND_ERRORS = (
    "ModuleNotFoundError",
    "No module named 'chimera'",
    'No module named "chimera"',
)


def _assert_no_module_not_found(testcase, completed_process, context: str):
    """Общая проверка: в выводе subprocess НЕТ ModuleNotFoundError.

    Это критическая регрессия — фактический баг, который фиксим (v5.1).
    Cron падал с ModuleNotFoundError, потому что python3 -c "from chimera..."
    запускался без PYTHONPATH и cwd != проектной директории.
    """
    combined = (completed_process.stdout or "") + (completed_process.stderr or "")
    for err_pattern in _MODULE_NOT_FOUND_ERRORS:
        testcase.assertNotIn(
            err_pattern, combined,
            f"{context}: обнаружен {err_pattern!r} в выводе subprocess — "
            f"это регрессия v5.1 (cron должен использовать wrapper-скрипт "
            f"с export PYTHONPATH, а не bare python3 -c \"from chimera...\").\n"
            f"--- stdout ---\n{completed_process.stdout}\n"
            f"--- stderr ---\n{completed_process.stderr}\n"
        )


def _is_import_failure(completed_process) -> bool:
    """Возвращает True, если ошибка subprocess — import-related
    (ModuleNotFoundError или подобное)."""
    combined = (completed_process.stdout or "") + (completed_process.stderr or "")
    return any(p in combined for p in _MODULE_NOT_FOUND_ERRORS)


# ────────────────────────────────────────────────────────────────────────────
#  Helper: запустить wrapper-скрипт в изолированном окружении (как cron)
# ────────────────────────────────────────────────────────────────────────────

def _run_script_as_cron(script_path: Path, log_path: Path | None = None) -> subprocess.CompletedProcess:
    """Запускает wrapper-скрипт через subprocess, эмулируя cron-окружение.

    Ключевые свойства:
      - cwd = tmpdir (НЕ проектная директория — cron обычно запускается
        с cwd=/ или cwd=/root, и `from chimera...` без PYTHONPATH падает).
      - PYTHONPATH НЕ выставлен (как у cron по умолчанию).
      - Скрипт сам должен выставить PYTHONPATH через `export` (это и есть
        фикс v5.1).

    Если log_path задан — заменяем целевой лог в скрипте на этот tmp-путь,
    чтобы не пытаться писать в /root/awg/awg_standalone.log (нет прав).
    """
    # Если в скрипте есть перенаправление в реальный лог (/root/awg/...),
    # подменяем на tmp-путь, иначе wrapper упадёт на PermissionError ещё
    # до импорта (что замаскирует настоящий результат теста).
    content = script_path.read_text()
    if log_path is not None:
        # Заменяем常见的 пути реальных логов на tmp-путь
        for real_log in (
            "/root/awg/awg_standalone.log",
            "/var/log/xray-node-health.log",
        ):
            content = content.replace(real_log, str(log_path))

    # Пишем подмененный скрипт во tmp (рядом с оригиналом, чтобы path был валиден)
    test_script = script_path.parent / (script_path.name + ".test_run.sh")
    test_script.write_text(content)
    test_script.chmod(0o755)

    # cwd = tmpdir (НЕ проектный root) — эмулируем cron
    cwd = tempfile.mkdtemp(prefix="cron_test_cwd_")
    try:
        # Запускаем скрипт. shell=False — вызываем скрипт напрямую.
        # ВАЖНО: НЕ передаём env= с PYTHONPATH — проверяем что скрипт
        # сам экспорит PYTHONPATH (это и есть фикс v5.1).
        env = os.environ.copy()
        # Удаляем PYTHONPATH если он был в окружении теста (иначе тест
        # не настоящий — cron-окружение без PYTHONPATH).
        env.pop("PYTHONPATH", None)
        # Удаляем _ chimera-специфичные переменные если есть
        for k in list(env.keys()):
            if "chimera" in k.lower():
                del env[k]
        return subprocess.run(
            ["/bin/bash", str(test_script)],
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env,
            timeout=30,
        )
    finally:
        try:
            import shutil
            shutil.rmtree(cwd, ignore_errors=True)
            test_script.unlink(missing_ok=True)
        except Exception:
            pass


# ============================================================================
#  TEST 1: AWG expiry cron — subprocess integration
# ============================================================================

class TestAwgExpiresCronSubprocess(unittest.TestCase):
    """Интеграционный тест: awgs_setup_expires_cron генерирует wrapper-скрипт,
    который РЕАЛЬНО запускается через subprocess из чужого cwd без
    ModuleNotFoundError.

    До v5.1 cron-файл содержал bare ``python3 -c "from chimera..."``,
    который падал с ModuleNotFoundError на каждом запуске. Реальный трейсбек
    с сервера пользователя zvshka подтвердил, что фича автоудаления истёкших
    AWG-клиентов НИКОГДА не срабатывала.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="awg_expires_cron_"))
        self._cron = self._tmpdir / "awg-standalone-expires"
        self._script = self._tmpdir / "awg-expires-check.sh"
        self._log = self._tmpdir / "test.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.awg_constants.AWGS_CRON_EXPIRES", self._cron),
            patch("chimera.modules.awg_constants.AWGS_CRON_EXPIRES_SCRIPT", self._script),
            # Лог-файл AWGS_LOG_FILE = /root/awg/awg_standalone.log — нет прав,
            # подменяем на tmp-путь.
            patch("chimera.modules.awg_constants.AWGS_LOG_FILE", self._log),
            # В awg_standalone.py импортируется AWGS_LOG_FILE в top-level,
            # поэтому патчим и там.
            patch("chimera.modules.awg_standalone.AWGS_LOG_FILE", self._log),
        )

    def test_generated_wrapper_script_runs_without_module_not_found(self):
        """КРИТИЧЕСКИЙ регрессионный тест: запуск wrapper-скрипта через
        subprocess.run() НЕ должен давать ModuleNotFoundError.

        До v5.1 cron генерил ``python3 -c "from chimera..."`` без PYTHONPATH
        — это падало с ModuleNotFoundError на каждом запуске cron'а.
        v5.1: cron генерит wrapper bash-скрипт с ``export PYTHONPATH`` и
        ``sys.path.insert(0, ...)`` — это работает.
        """
        from chimera.modules.awg_standalone import awgs_setup_expires_cron

        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            ok = awgs_setup_expires_cron()
        self.assertTrue(ok, "awgs_setup_expires_cron должен вернуть True")
        self.assertTrue(self._script.exists(),
                       "wrapper-скрипт должен быть создан")

        # Запускаем wrapper-скрипт как cron (cwd=tmpdir, без PYTHONPATH)
        result = _run_script_as_cron(self._script, log_path=self._log)

        # КРИТИЧЕСКАЯ регрессионная проверка
        _assert_no_module_not_found(self, result,
            "AWG expiry cron wrapper (v5.1 fix)")

        # Если returncode != 0 — проверяем что причина НЕ import-related
        # (env-специфичные ошибки типа PermissionError на /var/... допустимы
        # в test-окружении, они не связаны с фиксируемым багом).
        if result.returncode != 0:
            self.assertFalse(
                _is_import_failure(result),
                f"AWG expiry cron wrapper упал с import-related ошибкой "
                f"(returncode={result.returncode}):\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}\n"
            )

    def test_old_bare_python_c_pattern_does_fail_with_module_not_found(self):
        """POSITIVE CONTROL: старый ломанный паттерн (bare
        ``python3 -c "from chimera..."`` без PYTHONPATH с cwd=/tmp)
        ДЕЙСТВИТЕЛЬНО падает с ModuleNotFoundError.

        Этот тест гарантирует, что наш regression-тест (выше) реально
        ловит этот класс бага — а не просто случайно проходит. Если бы
        окружение теста magically резолвило ``from chimera...`` (например,
        через глобально установленный chimera package), regression-тест
        был бы бесполезен. Этот тест подтверждает, что без PYTHONPATH
        импорт действительно ломается.
        """
        cwd = tempfile.mkdtemp(prefix="positive_control_")
        try:
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            for k in list(env.keys()):
                if "chimera" in k.lower():
                    del env[k]
            # Тот самый ломанный паттерн, что был в коде до v5.1
            result = subprocess.run(
                ["/usr/bin/python3", "-c",
                 "from chimera.modules.awg_expires import awgs_expires_check; "
                 "awgs_expires_check()"],
                capture_output=True, text=True, cwd=cwd, env=env, timeout=15,
            )
            # ДОЛЖНО быть ModuleNotFoundError — иначе regression-тест бесполезен
            self.assertIn(
                "ModuleNotFoundError", result.stderr,
                f"POSITIVE CONTROL FAIL: bare python3 -c \"from chimera...\" "
                f"без PYTHONPATH НЕ упал с ModuleNotFoundError — значит "
                f"окружение теста magic'ом резолвит chimera, и regression-тест "
                f"выше бесполезен. stderr:\n{result.stderr}\n"
            )
        finally:
            import shutil
            shutil.rmtree(cwd, ignore_errors=True)


# ============================================================================
#  TEST 2: Telemt limits cron — subprocess integration
# ============================================================================

class TestTelemtLimitsCronSubprocess(unittest.TestCase):
    """Интеграционный тест: setup_iptables_accounting генерирует wrapper-скрипт
    для telemt-limits-check, который РЕАЛЬНО запускается через subprocess из
    чужого cwd без ModuleNotFoundError.

    До v5.1 cron генерил ``python3 -c "from chimera.modules.mtproto import
    mtproto_check_limits; ..."`` без PYTHONPATH — это падало с
    ModuleNotFoundError на каждом запуске. Квоты/expiry Telemt НИКОГДА
    реально не проверялись через cron, несмотря на зелёные юнит-тесты
    (тесты мокали вызов функции напрямую, не через subprocess).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="telemt_cron_"))
        self._cron = self._tmpdir / "telemt-stats"
        self._script = self._tmpdir / "telemt-limits-check.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.mtproto_stats.CRON_FILE", self._cron),
            patch("chimera.modules.mtproto_stats.LIMITS_CHECK_SCRIPT", self._script),
        )

    def test_generated_wrapper_script_runs_without_module_not_found(self):
        """КРИТИЧЕСКИЙ регрессионный тест: запуск wrapper-скрипта через
        subprocess.run() НЕ должен давать ModuleNotFoundError."""
        from unittest.mock import MagicMock
        from chimera.modules import mtproto_stats

        # Мокаем _run чтобы не вызывать реальные iptables-команды (их нет
        # в test-окружении). Нам важно проверить cron-генерацию + wrapper,
        # не саму установку iptables-цепочек.
        fake_run, _chains, _jumps = self._make_run_mock()
        with patch.object(mtproto_stats, "_run", fake_run), \
             self._patch()[0], self._patch()[1], \
             patch.object(mtproto_stats, "_persist_accounting_rules",
                          return_value=None):
            mtproto_stats.setup_iptables_accounting(8443)

        self.assertTrue(self._script.exists(),
                       "wrapper-скрипт telemt-limits-check должен быть создан")
        self.assertTrue(self._cron.exists(),
                       "cron-файл telemt-stats должен быть создан")

        # Проверяем cron-файл: должен ссылаться на wrapper-скрипт
        cron_content = self._cron.read_text()
        self.assertIn(str(self._script), cron_content,
                      "cron-файл должен ссылаться на wrapper-скрипт")
        # Regression: bare python3 -c "from chimera" в cron-файле НЕ должно быть
        self.assertNotIn('python3 -c "from chimera', cron_content,
                         "cron-файл НЕ должен содержать bare python3 -c \"from chimera...\"")

        # Запускаем wrapper-скрипт как cron (cwd=tmpdir, без PYTHONPATH)
        result = _run_script_as_cron(self._script)

        # КРИТИЧЕСКАЯ регрессионная проверка
        _assert_no_module_not_found(self, result,
            "Telemt limits cron wrapper (v5.1 fix)")

        # Если returncode != 0 — проверяем что причина НЕ import-related
        if result.returncode != 0:
            self.assertFalse(
                _is_import_failure(result),
                f"Telemt limits cron wrapper упал с import-related ошибкой "
                f"(returncode={result.returncode}):\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}\n"
            )

    def _make_run_mock(self):
        """Создаёт stateful mock для mtproto_stats._run (как в
        test_mtproto_stats.py) — эмулирует успешное создание цепочек."""
        from unittest.mock import MagicMock
        from chimera.modules.mtproto_stats import CHAIN_IN, CHAIN_OUT

        chains_exist = set()
        jumps = {}

        parent_map = {
            "INPUT":  (CHAIN_IN,  "dpt"),
            "OUTPUT": (CHAIN_OUT, "spt"),
        }
        direction_to_label = {"dport": "dpt", "sport": "spt"}

        def fake_run(cmd, capture=False, check=False):
            cmd = list(cmd)
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-L":
                chain_or_parent = cmd[2]
                if "-n" in cmd and "-v" not in cmd:
                    exists = chain_or_parent in chains_exist
                    return MagicMock(returncode=0 if exists else 1,
                                     stdout="chain" if exists else "",
                                     stderr="")
                if "-v" in cmd and "-n" in cmd:
                    lines = [f"Chain {chain_or_parent} (policy ACCEPT)"]
                    for (parent, chain, port, direction), count in jumps.items():
                        if parent != chain_or_parent or count <= 0:
                            continue
                        target, _ = parent_map.get(parent, (chain, "dpt"))
                        port_label = direction_to_label.get(direction, "dpt")
                        for _i in range(count):
                            line = (f"  0  0  {target}  "
                                    f"tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  "
                                    f"tcp {port_label}:{port}")
                            lines.append(line)
                    return MagicMock(returncode=0,
                                     stdout="\n".join(lines) + "\n",
                                     stderr="")
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-N":
                chains_exist.add(cmd[2])
                return MagicMock(returncode=0, stdout="", stderr="")
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-D":
                parent = cmd[2]
                key = None
                for (p, c, prt, d), cnt in list(jumps.items()):
                    if p == parent and c == (cmd[-1] if cmd[-1] != "-j" else None):
                        key = (p, c, prt, d); break
                if key and jumps.get(key, 0) > 0:
                    jumps[key] -= 1
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-I":
                parent = cmd[2]
                # Простое состояние: добавляем один jump для теста
                port = 8443
                chain = CHAIN_IN if parent == "INPUT" else CHAIN_OUT
                direction = "dport" if parent == "INPUT" else "sport"
                key = (parent, chain, port, direction)
                jumps[key] = jumps.get(key, 0) + 1
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        return fake_run, chains_exist, jumps


# ============================================================================
#  TEST 3: AWG cascade ru.zone cron — subprocess integration (bonus)
# ============================================================================

class TestAwgCascadeCronSubprocess(unittest.TestCase):
    """Интеграционный тест: _awgs_cascade_setup_cron генерирует wrapper-скрипт
    для еженедельного обновления ru.zone, который РЕАЛЬНО запускается через
    subprocess без ModuleNotFoundError.

    Бонус: тот же класс бага, что и в двух других cron'ах. Найден при
    ``grep -rn 'python3 -c' chimera/modules/*.py`` во время работы над
    v5.1 (третье место, не описанное в исходной задаче, но имеющее ту же
    root cause).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="awg_cascade_cron_"))
        self._cron = self._tmpdir / "awg-cascade-ru-update"
        self._script = self._tmpdir / "awg-cascade-ru-update.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.awg_cascade.AWGS_CRON_RU_UPDATE", self._cron),
            patch("chimera.modules.awg_cascade.AWGS_CRON_RU_UPDATE_SCRIPT", self._script),
        )

    def test_generated_wrapper_script_runs_without_module_not_found(self):
        """КРИТИЧЕСКИЙ регрессионный тест: запуск wrapper-скрипта через
        subprocess.run() НЕ должен давать ModuleNotFoundError."""
        from chimera.modules.awg_cascade import _awgs_cascade_setup_cron

        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_setup_cron()

        self.assertTrue(self._script.exists(),
                       "wrapper-скрипт awg-cascade-ru-update должен быть создан")

        # Запускаем wrapper-скрипт как cron (cwd=tmpdir, без PYTHONPATH)
        result = _run_script_as_cron(self._script, log_path=self._tmpdir / "test.log")

        # КРИТИЧЕСКАЯ регрессионная проверка
        _assert_no_module_not_found(self, result,
            "AWG cascade ru.zone cron wrapper (v5.1 bonus fix)")

        # Если returncode != 0 — проверяем что причина НЕ import-related
        if result.returncode != 0:
            self.assertFalse(
                _is_import_failure(result),
                f"AWG cascade cron wrapper упал с import-related ошибкой "
                f"(returncode={result.returncode}):\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}\n"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
