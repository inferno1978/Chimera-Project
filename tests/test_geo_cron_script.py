#!/usr/bin/env python3
"""
tests/test_geo_cron_script.py
───────────────────────────────────────────────────────────────────────────────
Smoke-тест для bash-скрипта автообновления geo-файлов (setup_geo_autoupdate).

Проверки:
  1. setup_geo_autoupdate() генерирует bash-скрипт без SyntaxError
     (валидация через `bash -n`).
  2. В сгенерированном скрипте присутствуют все зеркала из geo_mirrors.
  3. В скрипте есть проверка /root/ для ручного размещения (WinSCP).
  4. В скрипте есть multi-mirror fallback (цикл for url in ...).
  5. Cron-файл создаётся с правильной строкой расписания.

Это regression-тест на баг, который мы только что починили: до рефакторинга
cron-скрипт использовал ОДИН URL (raw.githubusercontent.com) — если GitHub
заблокирован, еженедельное обновление тихо проваливалось.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
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
    fake_core.SPLIT_TUNNEL_ENABLED = True
    sys.modules["chimera._core"] = fake_core


class TestGeoCronScript(unittest.TestCase):
    """Валидация bash-скрипта автообновления geo-файлов."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        # Перехватываем write_text для скрипта и cron-файла
        cls._captured = {}
        original_write_text = Path.write_text

        def patched(self, content, *a, **kw):
            if str(self) == "/usr/local/bin/xray-geo-update.sh":
                cls._captured['script'] = content
                return len(content)
            if str(self) == "/etc/cron.d/xray-geo-update":
                cls._captured['cron'] = content
                return len(content)
            return original_write_text(self, content, *a, **kw)

        cls._patch = patch.object(Path, 'write_text', patched)
        cls._patch.start()

        with patch.object(Path, 'chmod', lambda *a, **kw: None):
            from chimera.modules import geo_files
            geo_files.setup_geo_autoupdate()

        cls.script = cls._captured.get('script', '')
        cls.cron = cls._captured.get('cron', '')

    @classmethod
    def tearDownClass(cls):
        cls._patch.stop()

    # ── Существование ────────────────────────────────────────────────────
    def test_script_was_generated(self):
        self.assertTrue(self.script, "setup_geo_autoupdate() не сгенерировал скрипт")

    def test_cron_was_generated(self):
        self.assertTrue(self.cron, "setup_geo_autoupdate() не сгенерировал cron-файл")

    # ── Bash syntax ───────────────────────────────────────────────────────
    def test_bash_syntax_valid(self):
        """`bash -n` должен проходить — нет синтаксических ошибок."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(self.script)
            f.flush()
            tmp_path = f.name
        try:
            r = subprocess.run(["bash", "-n", tmp_path],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0,
                             f"bash -n failed:\n{r.stderr}\n--- script ---\n{self.script}")
        finally:
            os.unlink(tmp_path)

    # ── Multi-mirror fallback ────────────────────────────────────────────
    def test_script_contains_all_mirrors(self):
        """Все зеркала из geo_mirrors должны быть в скрипте."""
        from chimera.modules.geo_mirrors import get_all_mirrors
        for fname, urls in get_all_mirrors().items():
            for url in urls:
                with self.subTest(url=url):
                    self.assertIn(url, self.script,
                                  f"URL {url} отсутствует в скрипте")

    def test_script_has_bash_array_for_geosite(self):
        self.assertIn("GEOSITE_URLS=(", self.script)

    def test_script_has_bash_array_for_geoip(self):
        self.assertIn("GEOIP_URLS=(", self.script)

    def test_script_iterates_over_urls(self):
        """Должен быть цикл for url in ... — multi-mirror fallback."""
        self.assertIn('for url in "${urls[@]}"', self.script)

    # ── /root/ manual upload check ───────────────────────────────────────
    def test_script_checks_root_manual_upload(self):
        """Скрипт должен проверять /root/ перед тем как качать (WinSCP-friendly)."""
        self.assertIn('"/root/$name"', self.script)

    def test_script_logs_when_root_file_used(self):
        """Должен логировать когда взят файл из /root/."""
        self.assertIn("взят из /root/", self.script)

    # ── Min sizes ─────────────────────────────────────────────────────────
    def test_script_has_geosite_min_size(self):
        self.assertIn("GEOSITE_MIN=3000000", self.script)

    def test_script_has_geoip_min_size(self):
        self.assertIn("GEOIP_MIN=10000", self.script)

    # ── Multiple dest dirs (Xray lookup) ──────────────────────────────────
    def test_script_copies_to_multiple_dirs(self):
        """Должен копировать в /etc/xray, /usr/local/share/xray, /usr/local/etc/xray."""
        for d in ("/etc/xray", "/usr/local/share/xray", "/usr/local/etc/xray"):
            with self.subTest(d=d):
                self.assertIn(d, self.script)

    # ── Xray+nginx restart logic (preserved from before refactor) ────────
    def test_script_restarts_xray(self):
        self.assertIn("systemctl restart xray", self.script)

    def test_script_restarts_nginx_after_unix_socket(self):
        """BUGFIX: при REALITY+Unix-сокет нужно перезапустить nginx."""
        self.assertIn("systemctl restart nginx", self.script)
        self.assertIn("/dev/shm/*.socket", self.script)

    # ── Cron ──────────────────────────────────────────────────────────────
    def test_cron_has_sunday_schedule(self):
        """Cron: каждое воскресенье 03:00."""
        self.assertIn("0 3 * * 0", self.cron)

    def test_cron_points_to_script(self):
        self.assertIn("/usr/local/bin/xray-geo-update.sh", self.cron)

    def test_cron_runs_as_root(self):
        self.assertIn(" root ", self.cron)


if __name__ == "__main__":
    unittest.main(verbosity=2)
