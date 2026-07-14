#!/usr/bin/env python3
"""
tests/test_core_dns_redirect_integration.py
───────────────────────────────────────────────────────────────────────────────
Регрессионный тест Bug 4: _do_dns_redirect_health_screen() в _core.py
должен показывать РЕАЛЬНЫЙ порт из health_check_dns_redirect() (hc["port"]),
а не дефолт 5300.

На старом коде: hc.get('port', 5300) — ключа "port" в возвращаемом словаре
health_check_dns_redirect() не было, поэтому всегда рисовался дефолт 5300
даже если state.target_port=6000.

На новом коде: health_check_dns_redirect() возвращает "port" в dict,
и _do_dns_redirect_health_screen() использует это значение.

Тест:
  1. Мокаем health_check_dns_redirect() чтобы вернуть {"port": 6000, ...}.
  2. Захватываем stdout через contextlib.redirect_stdout.
  3. Вызываем _do_dns_redirect_health_screen() — НО она содержит input()
     в конце (для ожидания Enter). Мокаем builtin.input чтобы не висеть.
  4. Проверяем что "6000" есть в захваченном выводе.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core (как в test_tg_bot.py).

    Возвращает (fake_core, globals_dict) — globals_dict это тот самый dict
    который был передан в exec() и стал __globals__ для всех функций в
    _core.py. patch.dict на fake_core.__dict__ НЕ работает (это отдельная
    копия), нужно патчить именно globals_dict.
    """
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
    return fake_core, g


class TestBug4HealthScreenShowsActualPort(unittest.TestCase):
    """Bug 4: _do_dns_redirect_health_screen() должен показывать реальный
    порт из health_check_dns_redirect()['port'], а не дефолт 5300.

    На старом коде: в health_check_dns_redirect() НЕ было ключа "port",
    поэтому _do_dns_redirect_health_screen() через hc.get('port', 5300)
    всегда показывал 5300 — даже если state.target_port=6000.

    На новом коде: health_check_dns_redirect() возвращает "port": port
    в dict, и _do_dns_redirect_health_screen() использует это значение.
    """

    def setUp(self):
        self._fake_core, self._core_globals = _setup_core_in_sysmodules()

    def test_core_health_screen_shows_actual_port(self):
        """Мокаем health_check_dns_redirect(return_value={'port': 6000, ...}),
        вызываем _do_dns_redirect_health_screen() с захватом stdout,
        assertIn('6000', captured_output)."""
        # Получаем функцию из fake_core (она определена в _core.py)
        _do_dns_redirect_health_screen = self._fake_core._do_dns_redirect_health_screen

        # Мокаем health_check_dns_redirect чтобы вернуть port=6000
        fake_hc = {
            "enabled":            True,
            "port":               6000,  # ← Bug 4: это значение должно попасть в вывод
            "dnscrypt_active":    True,
            "port_listening_udp": True,
            "port_listening_tcp": True,
            "rules_applied":      True,
            "ipv6_supported":     False,
            "issues":             [],
            "recommendation":     "OK — DNS-редирект работает корректно",
        }

        # Захватываем stdout
        captured = io.StringIO()
        # Мокаем input() чтобы не висеть на "Нажмите Enter..."
        # Патчим health_check_dns_redirect в globals _do_dns_redirect_health_screen
        # (это self._core_globals — тот самый dict, переданный в exec()).
        # patch.dict на fake_core.__dict__ НЕ работает, т.к. fake_core.__dict__
        # это копия, а fn.__globals__ ссылается на оригинальный g.
        with patch("builtins.input", return_value=""), \
             redirect_stdout(captured), \
             patch.dict(self._core_globals,
                        {"health_check_dns_redirect": lambda: fake_hc}):
            _do_dns_redirect_health_screen()

        output = captured.getvalue()

        # На старом коде: hc.get('port', 5300) — нет ключа 'port' → 5300
        # На новом коде: hc['port'] = 6000 → в выводе должно быть 6000
        self.assertIn("6000", output,
                      f"Expected '6000' (actual port) in health-screen output, "
                      f"got:\n{output}")
        # Убеждаемся что 5300 НЕ появилось (это был бы признак бага)
        self.assertNotIn("5300", output,
                         f"Default port 5300 should NOT appear when state.port=6000, "
                         f"got:\n{output}")

    def test_core_health_screen_shows_default_port_when_not_in_state(self):
        """Дополнительная проверка: если health_check возвращает port=5300
        (например state пустой), то в выводе должно быть 5300."""
        _do_dns_redirect_health_screen = self._fake_core._do_dns_redirect_health_screen

        fake_hc = {
            "enabled":            False,
            "port":               5300,  # default
            "dnscrypt_active":    False,
            "port_listening_udp": False,
            "port_listening_tcp": False,
            "rules_applied":      False,
            "ipv6_supported":     False,
            "issues":             ["dnscrypt-proxy сервис не активен"],
            "recommendation":     "DNS-редирект выключен",
        }

        captured = io.StringIO()
        with patch("builtins.input", return_value=""), \
             redirect_stdout(captured), \
             patch.dict(self._core_globals,
                        {"health_check_dns_redirect": lambda: fake_hc}):
            _do_dns_redirect_health_screen()

        output = captured.getvalue()
        self.assertIn("5300", output,
                      f"Expected '5300' (default port) in output, got:\n{output}")

    def test_health_check_dns_redirect_returns_port_key(self):
        """Прямая проверка: health_check_dns_redirect() возвращает dict
        с ключом 'port'. На старом коде этого ключа не было."""
        from chimera.modules import dns_redirect
        # Мокаем все внешние вызовы чтобы получить детерминированный результат
        with patch("chimera.modules.dns_redirect.state_load",
                   return_value={"enabled": False, "target_port": 6000,
                                 "iface_filter": "awg0"}), \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._check_rules_applied",
                   return_value=False), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=False):
            hc = dns_redirect.health_check_dns_redirect()
        # Bug 4: ключ "port" должен присутствовать
        self.assertIn("port", hc,
                      "health_check_dns_redirect() must return 'port' key "
                      "(Bug 4: was missing in original commit 17e207b)")
        self.assertEqual(hc["port"], 6000,
                         f"Expected port=6000 from state, got: {hc['port']}")


if __name__ == "__main__":
    unittest.main()
