#!/usr/bin/env python3
"""
tests/test_ssl_certbot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ssl_certbot.py.

Покрывает:
  1. ensure_cert_fix_script — генерация bash-скрипта
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    sys.modules["chimera._core"] = fake_core


class TestEnsureCertFixScript(unittest.TestCase):
    """ensure_cert_fix_script — генерация bash-скрипта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._script = self._tmpdir / "fix-xray-certs.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_script_with_domain(self):
        """Тестируем через перехват Path — write_text/chmod на mock."""
        from chimera.modules import ssl_certbot
        # Функция: script_path = Path("/usr/local/bin/fix-xray-certs.sh")
        # затем script_path.write_text(content) + script_path.chmod(0o750)
        # Патчим Path чтобы вернуть mock_path для нужного аргумента
        captured_content = []

        def _fake_path(*args, **kwargs):
            p = Path(*args, **kwargs)
            if args and str(args[0]) == "/usr/local/bin/fix-xray-certs.sh":
                # Возвращаем mock, который записывает в captured_content
                mock = MagicMock()
                mock.write_text = lambda content: captured_content.append(content)
                mock.chmod = lambda mode: None
                mock.__str__ = lambda: str(self._script)
                return mock
            return p

        with patch.object(ssl_certbot, "Path", side_effect=_fake_path):
            result = ssl_certbot.ensure_cert_fix_script("vpn.example.com")
        self.assertEqual(len(captured_content), 1)
        content = captured_content[0]
        self.assertIn("vpn.example.com", content)
        self.assertIn("DOMAIN=", content)

    def test_script_has_chmod_750(self):
        """Проверяем что chmod вызывается с 0o750."""
        from chimera.modules import ssl_certbot
        chmod_calls = []

        def _fake_path(*args, **kwargs):
            p = Path(*args, **kwargs)
            if args and str(args[0]) == "/usr/local/bin/fix-xray-certs.sh":
                mock = MagicMock()
                mock.write_text = lambda content: None
                mock.chmod = lambda mode: chmod_calls.append(mode)
                return mock
            return p

        with patch.object(ssl_certbot, "Path", side_effect=_fake_path):
            ssl_certbot.ensure_cert_fix_script("vpn.example.com")
        self.assertIn(0o750, chmod_calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
