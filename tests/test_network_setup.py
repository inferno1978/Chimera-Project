#!/usr/bin/env python3
"""
tests/test_network_setup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/network_setup.py — configure_firewall().

Покрывает регрессию port_registry-интеграции (кейс DE-стенда 2026-09-29):
UFW-правила 443/8443 существовали ДО установки Chimera →
_ufw_allow_if_missing делал ранний return и порт НЕ попадал в port_registry
→ реестр врал, что порты свободны (conflict detection не работал).

Теперь при существующем UFW-правиле порт регистрируется постфактум
(force=True) — реестр знает правду независимо от истории UFW-правил.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_mtproto.py — патчит Path/os."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


_UFW_STATUS_ACTIVE = (
    "Status: active\n"
    "To                         Action      From\n"
    "--                         ------      ----\n"
    "22/tcp                     ALLOW IN    Anywhere\n"
    "80/tcp                     ALLOW IN    Anywhere\n"
    "443/tcp                    ALLOW IN    Anywhere\n"
)


class TestConfigureFirewallRegistersExistingRules(unittest.TestCase):
    """UFW-правило уже существует → порт всё равно регистрируется в реестре."""

    def setUp(self):
        self._core = _setup_core_in_sysmodules()

    def test_existing_ufw_rule_still_registers_port(self):
        from chimera.modules import network_setup as ns
        from chimera.modules import port_registry as pr

        tmpdir = Path(tempfile.mkdtemp())
        mark_file = tmpdir / "ufw" / "mark"

        def fake_run(cmd, **kw):
            m = MagicMock()
            m.returncode = 0
            m.stdout = _UFW_STATUS_ACTIVE if list(cmd[:2]) == ["ufw", "status"] else ""
            return m

        with patch.object(self._core, "command_exists",
                          side_effect=lambda c: c == "ufw"), \
             patch.object(self._core, "_run", side_effect=fake_run), \
             patch.object(self._core, "UFW_MARK_FILE", mark_file), \
             patch.object(self._core, "PROGRESS", MagicMock()), \
             patch.object(self._core, "info"), \
             patch.object(self._core, "warn"), \
             patch.object(self._core, "dim"), \
             patch.object(self._core, "success"), \
             patch.object(pr, "port_register",
                          return_value=(True, "ok")) as _mreg, \
             patch.object(pr, "ufw_open_port",
                          return_value=(True, "ok")) as _mopen:
            ns.configure_firewall()

        # Все три порта (22/80/443) уже открыты в UFW → порты обязаны
        # попасть в реестр (раньше — ранний return без регистрации).
        registered = sorted(
            (c.args[1] if len(c.args) > 1 else c.kwargs.get("port"))
            for c in _mreg.call_args_list
        )
        self.assertEqual(registered, [22, 80, 443])
        # UFW-правила НЕ дублируются — ufw_open_port не вызывался.
        _mopen.assert_not_called()
        # Файрволл завершён успешно.
        self.assertTrue(getattr(self._core, "STAGE_UFW_DONE", False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
