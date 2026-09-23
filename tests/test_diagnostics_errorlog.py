#!/usr/bin/env python3
"""
tests/test_diagnostics_errorlog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/diagnostics.py: проверка фильтра _BENIGN_PATTERNS
в _diag_check_error_log.

Сценарий бага (репорт пользователя):
  На всех 3 серверах в Chimera one-button diagnostics фиксировался
  варнинг "⚠ Split tunneling работает, есть замечания" без явной [WARN] строки.
  Причина: в error.log скапливались строки от REALITY-сканеров:

    [Info] transport/internet/tcp: REALITY: processed invalid connection
      from 18.218.118.203:50938: failed to read client hello

  Фильтр _BENIGN_PATTERNS не содержал паттернов "reality: processed invalid",
  "failed to read client hello", "invalid connection from" — строки попадали
  в critical-список и инкрементировали counters[2] (warnings), но выводились
  через _box_info (как [INFO]) без [WARN] маркера — отсюда диссонанс.

Фикс: расширить _BENIGN_PATTERNS + выводить critical как [WARN].
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from tests.test_diagnostics import _setup_core_in_sysmodules  # reuse helper


class TestBenignPatternsRealityScans(unittest.TestCase):
    """Проверка, что REALITY-сканерные строки теперь считаются benign."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import diagnostics
        self.diag = diagnostics

    def _is_benign_via_inner(self, line: str) -> bool:
        """Вызывает внутренний _is_benign из _diag_check_error_log.

        _is_benign определена локально в теле _diag_check_error_log — её
        нельзя импортировать напрямую. Поэтому проверяем через _BENIGN_PATTERNS:
        соберём список паттернов прямо из исходника и применим к строке.
        """
        import inspect
        src = inspect.getsource(self.diag._diag_check_error_log)
        # Извлекаем все строковые литералы из _BENIGN_PATTERNS = [...]
        import ast
        tree = ast.parse(src)
        patterns = []
        for node in ast.walk(tree):
            if isinstance(node, ast.List) and any(
                isinstance(c, ast.Constant) and isinstance(c.value, str)
                for c in node.elts
            ):
                # первый список в функции — это _BENIGN_PATTERNS
                patterns = [c.value for c in node.elts
                            if isinstance(c, ast.Constant) and isinstance(c.value, str)]
                break
        low = line.lower()
        return any(p in low for p in patterns)

    def test_reality_processed_invalid_is_benign(self):
        line = ("2026/09/23 20:41:18.510701 [Info] transport/internet/tcp: "
                "REALITY: processed invalid connection from 18.218.118.203:50938: "
                "failed to read client hello")
        self.assertTrue(self._is_benign_via_inner(line),
                        "REALITY: processed invalid connection должно быть benign")

    def test_failed_to_read_client_hello_is_benign(self):
        line = ("2026/09/23 03:50:00.453128 [Info] transport/internet/tcp: "
                "REALITY: processed invalid connection from 127.0.0.1:23502: "
                "failed to read client hello")
        self.assertTrue(self._is_benign_via_inner(line),
                        "failed to read client hello должно быть benign")

    def test_invalid_connection_from_is_benign(self):
        line = ("[Info] transport/internet/tcp: REALITY: processed "
                "invalid connection from 5.5.5.5:12345: failed to read client hello")
        self.assertTrue(self._is_benign_via_inner(line),
                        "invalid connection from должно быть benign")

    def test_invalid_user_is_benign(self):
        line = ("[Info] app/proxyman: invalid user >> email: nonexistent@example.com "
                "[from 1.2.3.4:5555]")
        self.assertTrue(self._is_benign_via_inner(line),
                        "invalid user должно быть benign")

    def test_rejected_by_reality_is_benign(self):
        line = ("[Info] transport/internet/tcp: connection rejected by REALITY "
                "from 8.8.8.8:9999: validation criteria not met")
        self.assertTrue(self._is_benign_via_inner(line),
                        "rejected by REALITY должно быть benign")

    def test_reality_failed_to_dial_dest_is_benign(self):
        """REALITY пишет [Info] о неудачном dial unix /dev/shm — это не ошибка."""
        line = ("2026/09/23 21:00:05.898218 [Info] transport/internet/tcp: "
                "REALITY: failed to dial dest: dial unix /dev/shm/30736465.socket: "
                "connect: no such file or directory")
        self.assertTrue(self._is_benign_via_inner(line),
                        "REALITY: failed to dial dest должно быть benign")

    def test_dial_unix_dev_shm_is_benign(self):
        line = ("[Info] transport/internet/tcp: dial unix /dev/shm/123.socket: "
                "connect: no such file or directory")
        self.assertTrue(self._is_benign_via_inner(line),
                        "dial unix /dev/shm должно быть benign")

    def test_real_error_still_critical(self):
        """Строка с настоящей ошибкой (не в benign) — НЕ benign."""
        line = "[Error] app/dns: failed to query DNS server 1.1.1.1: connection refused"
        self.assertFalse(self._is_benign_via_inner(line),
                         "Реальная DNS-ошибка НЕ должна быть benign")

    def test_geo_error_still_critical(self):
        """Строка с гео-ошибкой — НЕ benign (нужно решать)."""
        line = ("[Warning] infra/conf: JSON decode failed: geosite.dat is corrupted")
        self.assertFalse(self._is_benign_via_inner(line),
                         "Ошибка geosite.dat НЕ должна быть benign")

    def test_all_old_benign_patterns_still_benign(self):
        """Регресс: старые benign-паттерны не должны сломаться."""
        for line in [
            "2026/09/23 [Info] app/dispatcher: xtls rejected udp [1.2.3.4 => 5.6.7.8]",
            "2026/09/23 [Info] proxy/freedom: connection ends 0.0.0.0 -> 8.8.8.8",
            "2026/09/23 [Info] app/proxyman: authentication failed for user abc",
            "2026/09/23 [Warning] failed to set tcp_user_timeout: protocol not available",
        ]:
            self.assertTrue(self._is_benign_via_inner(line),
                            f"Старый benign-паттерн сломан: {line!r}")


class TestErrorLogWarnLevelOutput(unittest.TestCase):
    """Проверка, что critical-строки в error.log выводятся как [WARN], а не [INFO].

    Регресс-фикс: ранее использовался _box_info — из-за этого варнинг
    "Предупреждений: 1" появлялся в итоговом блоке БЕЗ видимой [WARN] строки.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import diagnostics
        self.diag = diagnostics

    def _run_error_log_check(self, lines: list, counters):
        """Запускает _diag_check_error_log с замоканным окружением."""
        import inspect
        src = inspect.getsource(self.diag._diag_check_error_log)

        # Подменяем core-функции и путь
        core = MagicMock()
        core._box_warn = MagicMock()
        core._box_info = MagicMock()
        core._box_dim  = MagicMock()
        core.DIAG_ERROR_LOG = MagicMock()
        core.DIAG_ERROR_LOG.exists.return_value = True
        core._BOX_W = 100
        core.BOLD = ""
        core.NC = ""
        core.YELLOW = ""
        core.GREEN = ""

        # Замокаем _diag_run, чтобы он вернул наши строки через tail
        fake_completed = MagicMock()
        fake_completed.stdout = "\n".join(lines)
        # Если строк нет — stdout пустой

        with patch.object(self.diag, "_core_module", return_value=core), \
             patch.object(self.diag, "_diag_run", return_value=fake_completed), \
             patch.object(self.diag, "_diag_head"), \
             patch.object(self.diag, "_diag_ok"), \
             patch.object(self.diag, "_diag_err"):
            self.diag._diag_check_error_log(counters)
        return core

    def test_reality_scans_dont_increment_warnings(self):
        """REALITY-сканерные строки НЕ должны увеличивать counters[2]."""
        counters = [0, 0, 0, 0]
        lines = [
            "2026/09/23 20:41:18.510701 [Info] transport/internet/tcp: "
            "REALITY: processed invalid connection from 18.218.118.203:50938: "
            "failed to read client hello",
            "2026/09/23 20:44:37.422161 [Info] transport/internet/tcp: "
            "REALITY: processed invalid connection from 18.218.118.203:42226: "
            "failed to read client hello",
            "2026/09/23 20:44:58.800576 [Info] transport/internet/tcp: "
            "REALITY: processed invalid connection from 18.218.118.203:44132: "
            "failed to read client hello",
        ]
        core = self._run_error_log_check(lines, counters)
        # counters[0] — total (тут _diag_chk не вызывается, только _box_warn/info)
        # counters[2] — warnings, должен быть 0 (все строки benign)
        self.assertEqual(counters[2], 0,
                         "REALITY-сканерные строки НЕ должны инкрементировать warnings")
        # counters[3] — errors, тоже 0
        self.assertEqual(counters[3], 0,
                         "REALITY-сканерные строки не должны быть errors")

    def test_real_critical_outputs_as_warn(self):
        """Если есть реальная нештатная ошибка — выводится [WARN] и counters[2]=1."""
        counters = [0, 0, 0, 0]
        lines = [
            "[Error] app/dns: failed to query DNS server 1.1.1.1: connection refused",
        ]
        core = self._run_error_log_check(lines, counters)
        self.assertEqual(counters[2], 1,
                         "Реальная нештатная ошибка должна инкрементировать warnings")
        # _box_warn должен быть вызван (хотя бы раз для critical)
        self.assertTrue(core._box_warn.called,
                        "Вывод critical-строк должен использовать _box_warn (FIX)")
        # Старый путь через _box_info не должен использоваться для critical-строк
        # _box_info может вызываться для benign-счётчика, но не для critical
        # Найдём вызов, который содержит "Нештатные" или "critical"
        info_calls = [str(c) for c in core._box_info.call_args_list]
        critical_info_calls = [c for c in info_calls if "Нештатные" in c or "critical" in c.lower()]
        self.assertEqual(critical_info_calls, [],
                          "Critical-строки НЕ должны выводиться через _box_info (старое поведение)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
