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


# ============================================================================
#  v5.0.6 REGRESSION TEST: правильное условие зелёного/жёлтого в блоке
#  «Сверка конфигурации» DNS Leak Test
# ============================================================================
# Коммит 038540f (v5.0.5) исправил визуальный баг — жёлтое "DNS уходит
# напрямую" рисовалось при активном DNSCrypt. НО он сделал это проверкой
# dnscrypt_active (процесс запущен), что является false negative:
# dnscrypt-proxy может быть active без применённых iptables-правил
# редиректа 53 порта — то есть без реального перехвата трафика.
#
# v5.0.6 исправляет условие: redirect_active = enabled AND rules_applied.
# Зелёный цвет показывается ТОЛЬКО когда трафик реально перехватывается.
#
# Тесты вызывают _render_dns_reconciliation_box() напрямую (мокая
# health_check_dns_redirect и _run для systemctl), не трогая сетевые
# методы 1-4 do_dns_leak_test.

class TestDnsReconciliationBoxV4256(unittest.TestCase):
    """5 кейсов для блока «Сверка конфигурации» (v5.0.6).

    Логика (см. _render_dns_reconciliation_box docstring):
      - loopback → зелёное "проксируется локально"
      - non-loopback + redirect_active (enabled=True, rules_applied=True)
        → зелёное "редирект активен"
      - non-loopback + redirect НЕ активен → жёлтое "уходит напрямую"
        (включая dnscrypt active но rules_applied=False — ключевой кейс бага)
      - non-loopback + health_check бросает исключение → жёлтое (fallback)
      - loopback=True → redirect-логика не влияет (зелёное "localhost")
    """

    def setUp(self):
        self._fake_core, self._core_globals = _setup_core_in_sysmodules()
        self._render = self._fake_core._render_dns_reconciliation_box

    def _make_completed_process(self, stdout="inactive", returncode=0):
        """Создаёт mock CompletedProcess для _run(['systemctl', 'is-active', ...])."""
        cp = MagicMock()
        cp.stdout = stdout
        cp.returncode = returncode
        cp.stderr = ""
        return cp

    def _run_box(self, configured_resolvers, fake_hc=None, hc_raises=False,
                 dnscrypt_stdout="inactive"):
        """Вызывает _render_dns_reconciliation_box с моками.

        Аргументы:
          configured_resolvers: список IP для resolv.conf
          fake_hc: dict который вернёт health_check_dns_redirect()
                   (None = функция не вызывается, но это не должно случаться)
          hc_raises: True = health_check_dns_redirect() бросает RuntimeError
          dnscrypt_stdout: stdout от `systemctl is-active dnscrypt-proxy`
                           ("active" или "inactive")

        Возвращает захваченный stdout.
        """
        captured = io.StringIO()

        # Мокаем _run в globals — он используется для systemctl is-active
        def fake_run(cmd, **kw):
            if cmd == ["systemctl", "is-active", "dnscrypt-proxy"]:
                return self._make_completed_process(stdout=dnscrypt_stdout)
            # На любой другой вызов — пустой результат
            return self._make_completed_process(stdout="", returncode=1)

        # Мокаем health_check_dns_redirect в globals
        if hc_raises:
            hc_value = MagicMock(side_effect=RuntimeError("state.json corrupted"))
        else:
            hc_value = lambda: fake_hc

        with patch("builtins.input", return_value=""), \
             redirect_stdout(captured), \
             patch.dict(self._core_globals, {
                 "_run": fake_run,
                 "health_check_dns_redirect": hc_value,
             }):
            self._render(configured_resolvers)

        return captured.getvalue()

    # ── Кейс 1: redirect активен → ЗЕЛЁНОЕ ─────────────────────────────────
    def test_non_loopback_redirect_active_shows_green(self):
        """Кейс 1: is_loopback=False, enabled=True, rules_applied=True
        → зелёное 'редирект активен', НЕ жёлтое."""
        fake_hc = {
            "enabled":       True,
            "rules_applied": True,
            "port":          5300,
            "dnscrypt_active": True,
            "issues":        [],
        }
        output = self._run_box(
            configured_resolvers=["8.8.8.8", "1.1.1.1"],
            fake_hc=fake_hc,
            dnscrypt_stdout="active",
        )
        # Зелёное сообщение про редирект присутствует
        self.assertIn("DNS-редирект активен", output,
                      f"Должно быть зелёное 'DNS-редирект активен', вывод:\n{output}")
        # Жёлтое предупреждение отсутствует
        self.assertNotIn("DNS-запросы уходят напрямую", output,
                         f"Не должно быть жёлтого предупреждения когда redirect активен, "
                         f"вывод:\n{output}")
        self.assertNotIn("минуя Xray", output)

    # ── Кейс 2: КЛЮЧЕВОЙ — dnscrypt active, но rules_applied=False ─────────
    def test_non_loopback_dnscrypt_active_no_rules_shows_yellow(self):
        """Кейс 2 (КЛЮЧЕВОЙ): is_loopback=False, enabled=True,
        rules_applied=False (но dnscrypt-proxy active) → ЖЁЛТОЕ, не зелёное.

        Это именно тот баг, который был в v5.0.5/038540f — код проверял
        dnscrypt_active и показывал зелёное, хотя реальной перехватки нет
        (правила iptables не применены). v5.0.6 исправляет это.
        """
        fake_hc = {
            "enabled":       True,
            "rules_applied": False,   # ← КЛЮЧЕВОЙ момент: правила НЕ применены
            "port":          5300,
            "dnscrypt_active": True,  # ← сервис активен, но трафик не перехватывается
            "issues":        ["редирект включён в state, но правила в iptables отсутствуют"],
        }
        output = self._run_box(
            configured_resolvers=["8.8.8.8", "1.1.1.1"],
            fake_hc=fake_hc,
            dnscrypt_stdout="active",  # systemctl is-active dnscrypt-proxy → active
        )
        # Жёлтое предупреждение должно присутствовать — реальный риск
        self.assertIn("DNS-запросы уходят напрямую", output,
                      f"Должно быть жёлтое предупреждение когда rules_applied=False, "
                      f"вывод:\n{output}")
        self.assertIn("минуя Xray", output)
        # Зелёное "редирект активен" НЕ должно появляться
        self.assertNotIn("DNS-редирект активен", output,
                         f"Не должно быть зелёного 'редирект активен' когда rules_applied=False "
                         f"(баг v5.0.5/038540f), вывод:\n{output}")
        # Но "DNSCrypt-proxy: активен" должен быть (потому что dnscrypt_stdout=active)
        # — это корректно, сервис действительно запущен, просто редиректа нет
        self.assertIn("активен", output)

    # ── Кейс 3: redirect выключен → ЖЁЛТОЕ ─────────────────────────────────
    def test_non_loopback_redirect_disabled_shows_yellow(self):
        """Кейс 3: is_loopback=False, enabled=False → жёлтое как раньше."""
        fake_hc = {
            "enabled":       False,
            "rules_applied": False,
            "port":          5300,
            "dnscrypt_active": False,
            "issues":        [],
        }
        output = self._run_box(
            configured_resolvers=["8.8.8.8"],
            fake_hc=fake_hc,
            dnscrypt_stdout="inactive",
        )
        self.assertIn("DNS-запросы уходят напрямую", output,
                      f"Должно быть жёлтое когда redirect выключен, вывод:\n{output}")
        self.assertNotIn("DNS-редирект активен", output)

    # ── Кейс 4: health_check_dns_redirect() бросает исключение ─────────────
    def test_non_loopback_health_check_raises_shows_yellow(self):
        """Кейс 4: is_loopback=False, health_check_dns_redirect() бросает
        исключение → жёлтое (fallback), экран не падает."""
        output = self._run_box(
            configured_resolvers=["8.8.8.8"],
            fake_hc=None,
            hc_raises=True,
            dnscrypt_stdout="inactive",
        )
        # Не должно быть зелёного (мы не знаем состояние редиректа —
        # не маскируем потенциальную утечку)
        self.assertNotIn("DNS-редирект активен", output,
                         f"Не должно быть зелёного когда health_check упал, вывод:\n{output}")
        # Жёлтое должно быть (fallback = безопасный default)
        self.assertIn("DNS-запросы уходят напрямую", output,
                      f"Должно быть жёлтое (fallback) когда health_check упал, "
                      f"вывод:\n{output}")
        # Блока вообще не должно упасть — функция должна отработать
        # и напечатать заголовок "Сверка конфигурации"
        self.assertIn("Сверка конфигурации", output)

    # ── Кейс 5: loopback → ЗЕЛЁНОЕ "localhost", redirect не влияет ─────────
    def test_loopback_shows_localhost_green_regardless_of_redirect(self):
        """Кейс 5: is_loopback=True → зелёное 'localhost — проксируется
        локально', redirect-логика не вызывается вообще (или вызывается,
        но не влияет на результат).

        Проверяем что зелёная "localhost" ветка не полагается на
        redirect_active — даже если redirect_active=False, loopback
        всё равно показывает зелёное.
        """
        # Передаём redirect_active=False (enabled=False, rules_applied=False)
        # — но loopback должен всё равно дать зелёное
        fake_hc = {
            "enabled":       False,
            "rules_applied": False,
            "port":          5300,
            "dnscrypt_active": False,
            "issues":        [],
        }
        output = self._run_box(
            configured_resolvers=["127.0.0.1"],
            fake_hc=fake_hc,
            dnscrypt_stdout="inactive",
        )
        # Зелёное "localhost" присутствует
        self.assertIn("localhost", output)
        self.assertIn("проксируется локально", output,
                      f"Должно быть 'проксируется локально' для loopback, "
                      f"вывод:\n{output}")
        # Жёлтое "уходит напрямую" отсутствует
        self.assertNotIn("DNS-запросы уходят напрямую", output,
                         f"Loopback не должен давать жёлтое, вывод:\n{output}")
        # "редирект активен" тоже отсутствует — это другая зелёная ветка
        self.assertNotIn("DNS-редирект активен", output,
                         f"Loopback использует 'localhost' ветку, не 'редирект активен', "
                         f"вывод:\n{output}")


if __name__ == "__main__":
    unittest.main()
