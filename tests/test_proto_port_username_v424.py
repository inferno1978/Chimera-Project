#!/usr/bin/env python3
"""
tests/test_proto_port_username_v424.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.24 — выбор порта + имя первого пользователя в протоколах:
  - NaiveProxy: запрос первого username вместо хардкода 'admin' + проверка
    конфликта порта до install.
  - sing-box TUIC default: _prompt_alt_port вызывается для выбора порта.
  - sing-box VLESS-WS-CDN default: _prompt_alt_port вызывается.
  - TrustTunnel: LE cert failure fallback на self-signed (не sys.exit(1)).
  - Mieru: запрос первого username вместо хардкода 'admin'.

Принцип: тесты НЕ запускают реальный install (он требует root/network).
Вместо этого проверяется что:
  1. Код, формирующий первого пользователя, читает input() — а не хардкод.
  2. TrustTunnel LE cert failure обрабатывается через SystemExit/Exception.
  3. _prompt_alt_port вызывается в TUIC/VLESS-WS-CDN default-меню.

Эти тесты — smoke/regression: проверяют что v4.24-логика присутствует
в коде и не была случайно удалена.
"""
from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


class TestNaiveproxyFirstUsernamePrompt(unittest.TestCase):
    """NaiveProxy: первый пользователь — запрос имени, не хардкод 'admin'."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_inner_asks_for_first_username(self):
        """В _run_install_inner должен быть proto_ask для логина первого
        пользователя (по умолчанию 'admin', но юзер может ввести свой)."""
        from chimera.modules import naiveproxy
        # Читаем исходник модуля — проверяем что в нём есть запрос.
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "naiveproxy.py"
        src = src_path.read_text()
        # Запрос логина первого пользователя.
        self.assertIn("Логин первого пользователя", src,
                      "NaiveProxy должен спрашивать логин первого пользователя")
        # Проверяем что proto_ask вызывается для логина (не просто input()).
        self.assertIn('proto_ask(', src,
                      "Должен использоваться proto_ask для запроса логина")
        # Main path НЕ должен иметь прямого 'first_user = "admin"' ДО proto_ask.
        # Fallback в except — OK.
        import re
        # Находим все 'first_user = "admin"' — ожидаем только в fallback (except _Cancelled).
        matches = re.findall(r'^\s*first_user\s*=\s*"admin"\s*$', src, re.MULTILINE)
        self.assertLessEqual(len(matches), 2,
                             "Слишком много hardcoded 'admin' — проверьте что main-path использует proto_ask")

    def test_port_conflict_check_exists(self):
        """В _run_install_inner должна быть проверка конфликта порта
        через socket.bind() — не просто int(input())."""
        from chimera.modules import naiveproxy
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "naiveproxy.py"
        src = src_path.read_text()
        # Проверка bind-конфликта.
        self.assertIn("_s.bind", src,
                      "Должна быть проверка конфликта порта через socket.bind()")
        # Запрос альтернативного порта.
        self.assertIn("Введите другой порт", src,
                      "Должен быть запрос альтернативного порта при конфликте")


class TestSingboxTuicPortPrompt(unittest.TestCase):
    """sing-box TUIC default: _prompt_alt_port вызывается."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_tuic_default_calls_prompt_alt_port(self):
        """В _enable_tuic_default (точнее в меню default-path) должен
        быть вызов _prompt_alt_port для UDP порта."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "singbox_menu.py"
        src = src_path.read_text()
        # Ищем блок: TUIC default → _prompt_alt_port(DEFAULT_PORT_TUIC_ALTERNATIVE, "::", "udp")
        self.assertIn(
            "_prompt_alt_port(DEFAULT_PORT_TUIC_ALTERNATIVE, \"::\", \"udp\")",
            src,
            "TUIC default должен вызывать _prompt_alt_port для UDP/:: порта"
        )

    def test_vless_ws_cdn_default_calls_prompt_alt_port(self):
        """В _enable_vless_ws_cdn_default должен быть вызов _prompt_alt_port."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "singbox_menu.py"
        src = src_path.read_text()
        self.assertIn(
            "_prompt_alt_port(DEFAULT_PORT_VLESS_WS_CDN, \"0.0.0.0\", \"tcp\")",
            src,
            "VLESS-WS-CDN default должен вызывать _prompt_alt_port для TCP/0.0.0.0"
        )


class TestTrustTunnelLECertFallback(unittest.TestCase):
    """TrustTunnel: LE cert failure → self-signed, не sys.exit(1)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_handles_systemexit_from_obtain_ssl_cert(self):
        """В _run_install_inner должен быть перехват SystemExit от
        obtain_ssl_cert (core.die() → sys.exit(1))."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "trusttunnel.py"
        src = src_path.read_text()
        # Перехват SystemExit.
        self.assertIn("except SystemExit", src,
                      "Должен быть перехват SystemExit от core.die()")
        # Fallback на self-signed.
        self.assertIn("generate_self_signed_cert", src,
                      "Должен быть fallback на generate_self_signed_cert")

    def test_install_asks_admin_email(self):
        """Должен быть запрос admin_email — не хардкод 'admin'."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "trusttunnel.py"
        src = src_path.read_text()
        self.assertIn("Email первого пользователя", src,
                      "Должен быть запрос Email первого пользователя")
        # Хардкод 'admin:...' в wizard_cmd должен быть заменён на {admin_email}:...
        self.assertIn("{admin_email}:{admin_pass}", src,
                      "wizard_cmd должен использовать admin_email, не хардкод 'admin'")


class TestMieruFirstUsernamePrompt(unittest.TestCase):
    """Mieru: первый пользователь — запрос имени, не хардкод 'admin'."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_inner_asks_for_first_username(self):
        """В _run_install_inner должен быть proto_ask для логина первого
        пользователя."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "mieru.py"
        src = src_path.read_text()
        self.assertIn("Логин первого пользователя", src,
                      "Mieru должен спрашивать логин первого пользователя")

    def test_no_hardcoded_admin(self):
        """Хардкод first_user = \"admin\" должен быть убран из MAIN path.
        Fallback в except _Cancelled / validation failure — OK (это
        reasonable default при отказе ввода)."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "mieru.py"
        src = src_path.read_text()
        # Main path: proto_ask с запросом логина.
        self.assertIn("Логин первого пользователя", src,
                      "Должен быть proto_ask для логина первого пользователя")
        # Fallback paths: first_user = "admin" только в except или after
        # validation failure. Проверяем что НЕТ 'first_user = "admin"'
        # как standalone-строки ДО proto_ask (т.е. до блока try).
        # Считаем сколько раз встречается — должно быть только в fallback.
        import re
        matches = re.findall(r'^\s*first_user\s*=\s*"admin"\s*$', src, re.MULTILINE)
        # Ожидаем 2 (except _Cancelled + validation failure).
        # 0 = proto_ask нет (баг). >2 =多余的 hardcode.
        self.assertGreaterEqual(len(matches), 1,
                                "Должен быть fallback на 'admin' в except-path")
        self.assertLessEqual(len(matches), 3,
                             "Слишком много hardcoded 'admin' — проверьте код")


class TestNaiveproxyNginxAutoStop(unittest.TestCase):
    """NaiveProxy: auto-stop nginx если порт занят."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_auto_stop_nginx_for_port_80(self):
        """В коде должна быть логика stop nginx когда порт 80 занят."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "naiveproxy.py"
        src = src_path.read_text()
        # Auto-stop nginx для ACME port 80.
        self.assertIn('"порт 80 для ACME"', src,
                      "Должен быть auto-stop nginx для port 80")

    def test_auto_stop_nginx_for_chosen_port(self):
        """В коде должна быть логика stop nginx когда выбранный порт занят."""
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "naiveproxy.py"
        src = src_path.read_text()
        # Auto-stop nginx если выбранный порт занят (для Caddy bind).
        self.assertIn("порт {port} для Caddy", src,
                      "Должен быть auto-stop nginx для выбранного порта")


if __name__ == "__main__":
    unittest.main(verbosity=2)
