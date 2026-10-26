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


class TestSysctlBufferAlignment(unittest.TestCase):
    """99-vless-performance.conf применяется ПОСЛЕДНИМ в /etc/sysctl.d
    (lexicographic: awg-standalone < csqtt < sysctl < telemt < vless).

    Раньше шаблон писал rmem/wmem_default = 1048576 и после ребута
    перезаписывал 7500000 из 99-awg-standalone.conf → AWG-диагностика
    показывала WARN на нодах с xray+AWG. Значения выровнены с
    AWGS_SYSCTL_TARGETS (см. также awg_constants.py).
    """

    def test_vless_conf_defaults_aligned_with_awg_target(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "network_setup.py").read_text()
        self.assertIn("net.core.rmem_default = 7500000", src)
        self.assertIn("net.core.wmem_default = 7500000", src)
        # легаси-значение не должно возвращаться
        self.assertNotIn("net.core.rmem_default = 1048576", src)
        self.assertNotIn("net.core.wmem_default = 1048576", src)

    def test_awg_target_constants_match(self):
        """Синхрон: vless-шаблон = цели AWG (7500000) — сверка констант."""
        from chimera.modules.awg_constants import AWGS_SYSCTL_TARGETS
        self.assertEqual(AWGS_SYSCTL_TARGETS["net.core.rmem_default"], 7500000)
        self.assertEqual(AWGS_SYSCTL_TARGETS["net.core.wmem_default"], 7500000)


class TestIpForwardPreserve(unittest.TestCase):
    """fix 26.10 (cascade-exit «чёрная дыра»): шаблон не опускает ip_forward.

    E2E ee1 (203.0.113.210): лексический порядок sysctl.d —
    99-awg-standalone.conf < 99-vless-performance.conf — заставлял
    vless-файл побеждать при загрузке; его `else 0` гасил форвардинг
    AWG-exit-ноды: туннели живы (handshake свежий), MASQUERADE на
    месте, а данные не форвардятся — «чёрная дыра» каскада.
    Теперь: Mode B ИЛИ активное значение 1 → пишем 1.
    """

    def test_ip_forward_never_lowered_below_active(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "network_setup.py").read_text()
        # preserve-if-1 форма в обеих строках шаблона
        self.assertIn(
            'net.ipv4.ip_forward = {1 if (INSTALL_MODE == "B" or _ipfwd_keep) else 0}',
            src)
        self.assertIn(
            'net.ipv6.conf.all.forwarding = {1 if (INSTALL_MODE == "B" or _ipfwd_keep) else 0}',
            src)
        # чтение активного значения присутствует
        self.assertIn('_ipfwd_keep = Path("/proc/sys/net/ipv4/ip_forward"', src)
        # старая форма (безусловный 0 в режиме A) не должна возвращаться
        self.assertNotIn('{1 if INSTALL_MODE == "B" else 0}', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
