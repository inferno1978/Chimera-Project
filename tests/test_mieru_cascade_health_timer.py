"""Unit-тесты systemd-юнитов mieru_cascade: расписание health-таймера.

Task 23: сокращение интервала 2 мин -> 1 мин (OnCalendar=*:0/1) для
минимизации окна медленного пути новых GGC-IP (querylog-harvest
добирает их только на следующем тике). Тест фиксирует контракт
таймера: ежеминутный календарь, ограниченный AccuracySec (дефолт
systemd 1 мин давал бы фазовый дрейф до +60с), Persistent и
корректный Install-таргет; плюс регрессия «0/2 не вернуть».
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from chimera.modules import mieru_cascade


class _UnitsTmpBase(unittest.TestCase):
    """_write_units с юнит-путями в tmpdir + _run под моком."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: _rmtree(self.tmp))
        self.unit_hop = self.tmp / "mieru-hop@.service"
        self.unit_reds = self.tmp / "mieru-cascade-redsocks@.service"
        self.unit_routing = self.tmp / "mieru-cascade-routing.service"
        self.unit_health = self.tmp / "mieru-cascade-health.service"
        self.unit_timer = self.tmp / "mieru-cascade-health.timer"
        self.wrapper = self.tmp / "mieru-cascade-health.sh"

    def _write_units(self):
        calls = []
        m = MagicMock()
        m._MIERU_BIN = "/usr/local/bin/mieru"
        with patch.object(mieru_cascade, "_UNIT_HOP", self.unit_hop), \
             patch.object(mieru_cascade, "_UNIT_REDSOCKS", self.unit_reds), \
             patch.object(mieru_cascade, "_UNIT_ROUTING", self.unit_routing), \
             patch.object(mieru_cascade, "_UNIT_HEALTH", self.unit_health), \
             patch.object(mieru_cascade, "_UNIT_HEALTH_T", self.unit_timer), \
             patch.object(mieru_cascade, "_HEALTH_WRAPPER", self.wrapper), \
             patch.object(mieru_cascade, "_mieru", return_value=m), \
             patch.object(mieru_cascade, "_redsocks_path",
                          return_value="/usr/sbin/redsocks"), \
             patch.object(mieru_cascade, "_run",
                          side_effect=lambda *a, **k: calls.append(a)):
            mieru_cascade._write_units()
        return calls


def _rmtree(p: Path):
    import shutil
    shutil.rmtree(p, ignore_errors=True)


class TestHealthTimerSchedule(_UnitsTmpBase):
    def test_every_minute_calendar(self):
        """Таймер ежеминутный: OnCalendar=*:0/1 + AccuracySec=10s."""
        self._write_units()
        timer = self.unit_timer.read_text()
        self.assertIn("OnCalendar=*:0/1", timer)
        self.assertIn("AccuracySec=10s", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("WantedBy=timers.target", timer)

    def test_no_regression_to_two_minutes(self):
        """Регрессия: старое */2 расписание не должно вернуться."""
        self._write_units()
        timer = self.unit_timer.read_text()
        self.assertNotIn("0/2", timer)

    def test_daemon_reload_after_write(self):
        """После записи юнитов обязателен systemctl daemon-reload."""
        calls = self._write_units()
        self.assertTrue(
            any(c and list(c[0])[:2] == ["systemctl", "daemon-reload"]
                for c in calls),
            f"daemon-reload не вызван: {calls}")


class TestHealthServiceUnit(_UnitsTmpBase):
    def test_service_oneshot_no_user(self):
        """Service-юнит тика: oneshot, ExecStart=wrapper, без User=
        (root — ipset/iptables требуют; фикс деплоя 01.10)."""
        self._write_units()
        service = self.unit_health.read_text()
        self.assertIn("Type=oneshot", service)
        self.assertIn("ExecStart=", service)
        self.assertNotIn("User=", service)

    def test_wrapper_written_executable(self):
        """Wrapper пишется и получает +x (иначе таймер умрёт на EACCES)."""
        self._write_units()
        self.assertTrue(self.wrapper.exists())
        self.assertEqual(self.wrapper.stat().st_mode & 0o777, 0o755)
        text = self.wrapper.read_text()
        self.assertIn("health_tick_cli", text)
        self.assertIn("PYTHONPATH", text)


if __name__ == "__main__":
    unittest.main()
