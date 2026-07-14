#!/usr/bin/env python3
"""
tests/test_smoke_test.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/smoke_test.py.

Покрывает:
  1. SNI lookup — берётся из state.json ключ 'domain' (не 'param_domain')
  2. TLS alert recognition — 'unrecognized_name' = сервер жив
  3. TCP connect — timeout, connection refused, success
  4. smoke_test_xray — полный flow с моками

Регрессия: баг когда SNI брался из state.get('param_domain') (None) →
fallback на 127.0.0.1 → REALITY отклонял → false-positive warning.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py через exec и регистрирует в sys.modules."""
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
    return fake_core


class TestSmokeTestSniLookup(unittest.TestCase):
    """SNI должен браться из state.json ключ 'domain', не 'param_domain'."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict: dict):
        """Патчит _STATE_FILE в smoke_test на временный файл с state_dict."""
        self._state_file.write_text(json.dumps(state_dict))
        return patch("chimera.modules.smoke_test._STATE_FILE",
                     self._state_file)

    def test_sni_from_domain_key(self):
        """SNI берётся из state['domain'] — правильный ключ."""
        from chimera.modules import smoke_test
        with self._patch_state({"domain": "example.com", "server_port": 443,
                                "protocol_mode": "reality"}):
            state = smoke_test._read_state()
            sni = state.get('domain') or state.get('param_domain') or '127.0.0.1'
            self.assertEqual(sni, "example.com")

    def test_sni_not_from_param_domain(self):
        """Если state.json не содержит 'domain', но содержит 'param_domain' —
        fallback на param_domain (для обратной совместимости)."""
        from chimera.modules import smoke_test
        with self._patch_state({"param_domain": "legacy.com", "server_port": 443}):
            state = smoke_test._read_state()
            # 'domain' отсутствует → fallback на 'param_domain'
            sni = state.get('domain') or state.get('param_domain') or '127.0.0.1'
            self.assertEqual(sni, "legacy.com")

    def test_sni_fallback_to_host_when_no_domain(self):
        """Если state.json не содержит ни 'domain' ни 'param_domain' — fallback на host."""
        from chimera.modules import smoke_test
        with self._patch_state({"server_port": 443, "protocol_mode": "reality"}):
            state = smoke_test._read_state()
            sni = state.get('domain') or state.get('param_domain') or '127.0.0.1'
            self.assertEqual(sni, "127.0.0.1")

    def test_sni_regression_param_domain_returns_none(self):
        """Регрессия: state.get('param_domain') возвращает None когда ключ 'domain'."""
        from chimera.modules import smoke_test
        with self._patch_state({"domain": "example.com", "server_port": 443}):
            state = smoke_test._read_state()
            # Старый баг: state.get('param_domain') = None даже когда domain есть
            self.assertIsNone(state.get('param_domain'))
            # Фикс: state.get('domain') возвращает правильное значение
            self.assertEqual(state.get('domain'), "example.com")


class TestTlsHandshakeAlertRecognition(unittest.TestCase):
    """_tls_handshake должен распознавать TLS alerts как 'сервер жив'."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_unrecognized_name_treated_as_server_alive(self):
        """Регрессия: 'unrecognized_name' = сервер жив, не провал.

        REALITY отклоняет SNI=127.0.0.1 с TLS alert 'unrecognized_name'.
        Python ssl обёртывает это в SSLError('tlsv1 unrecognized name').
        Раньше это не распознавалось как 'сервер ответил' → false-positive.
        """
        import ssl as _ssl
        from chimera.modules import smoke_test

        # Мокаем socket.create_connection чтобы вернуть mock сокет
        mock_sock = MagicMock()
        mock_sock.settimeout = MagicMock()

        # Мокаем ssl.create_default_context чтобы wrap_socket выбросил SSLError
        mock_ctx = MagicMock()
        mock_ctx.check_hostname = False
        mock_ctx.verify_mode = _ssl.CERT_NONE
        # wrap_socket должен выбросить SSLError с 'unrecognized name'
        err = _ssl.SSLError(1, "tlsv1 unrecognized name")
        mock_ctx.wrap_socket = MagicMock(side_effect=err)

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            ok, note = smoke_test._tls_handshake("127.0.0.1", 443, 5.0, sni="127.0.0.1")
            self.assertTrue(ok, "unrecognized_name должен считаться 'сервер жив', "
                                "не провалом. Регрессия: раньше возвращал False.")
            self.assertIn("сервер ответил", note)

    def test_alert_treated_as_server_alive(self):
        """Стандартный TLS alert = сервер жив."""
        import ssl as _ssl
        from chimera.modules import smoke_test

        mock_sock = MagicMock()
        mock_ctx = MagicMock()
        err = _ssl.SSLError(1, "SSL alert number 40")
        mock_ctx.wrap_socket = MagicMock(side_effect=err)

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            ok, note = smoke_test._tls_handshake("127.0.0.1", 443, 5.0)
            self.assertTrue(ok)

    def test_handshake_failure_treated_as_server_alive(self):
        """'handshake failure' в сообщении = сервер жив."""
        import ssl as _ssl
        from chimera.modules import smoke_test

        mock_sock = MagicMock()
        mock_ctx = MagicMock()
        err = _ssl.SSLError(1, "SSL handshake failure")
        mock_ctx.wrap_socket = MagicMock(side_effect=err)

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            ok, note = smoke_test._tls_handshake("127.0.0.1", 443, 5.0)
            self.assertTrue(ok)

    def test_timeout_treated_as_failure(self):
        """Socket timeout = провал (сервер не отвечает)."""
        import socket as _socket
        from chimera.modules import smoke_test

        mock_sock = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(side_effect=_socket.timeout())

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            ok, note = smoke_test._tls_handshake("127.0.0.1", 443, 5.0)
            self.assertFalse(ok)
            self.assertIn("timeout", note.lower())

    def test_connection_refused_treated_as_failure(self):
        """Connection refused = провал (порт не слушает)."""
        from chimera.modules import smoke_test

        with patch("socket.create_connection",
                   side_effect=ConnectionRefusedError()):
            ok, note = smoke_test._tls_handshake("127.0.0.1", 443, 5.0)
            self.assertFalse(ok)
            self.assertIn("refused", note.lower())

    def test_successful_handshake(self):
        """Успешный TLS handshake = OK."""
        import ssl as _ssl
        from chimera.modules import smoke_test

        mock_sock = MagicMock()
        mock_tls = MagicMock()
        mock_tls.version = MagicMock(return_value="TLSv1.3")
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(return_value=mock_tls)

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            ok, note = smoke_test._tls_handshake("example.com", 443, 5.0,
                                                  sni="example.com")
            self.assertTrue(ok)
            self.assertEqual(note, '')


class TestTcpConnect(unittest.TestCase):
    """_tcp_connect — проверка TCP соединения."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_successful_connect(self):
        from chimera.modules import smoke_test
        with patch("socket.create_connection"):
            ok, err = smoke_test._tcp_connect("127.0.0.1", 443, 5.0)
            self.assertTrue(ok)
            self.assertEqual(err, '')

    def test_timeout(self):
        import socket as _socket
        from chimera.modules import smoke_test
        with patch("socket.create_connection", side_effect=_socket.timeout()):
            ok, err = smoke_test._tcp_connect("127.0.0.1", 443, 5.0)
            self.assertFalse(ok)
            self.assertIn("timeout", err.lower())

    def test_connection_refused(self):
        from chimera.modules import smoke_test
        with patch("socket.create_connection",
                   side_effect=ConnectionRefusedError()):
            ok, err = smoke_test._tcp_connect("127.0.0.1", 443, 5.0)
            self.assertFalse(ok)
            self.assertIn("refused", err.lower())


class TestSmokeTestXrayFullFlow(unittest.TestCase):
    """smoke_test_xray — полный flow с моками."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_reality_mode_uses_domain_as_sni(self):
        """REALITY режим: SNI берётся из state['domain'].

        Регрессия: раньше брался state['param_domain'] = None → SNI=127.0.0.1
        → REALITY отклонял → false 'Xray не отвечает'.
        """
        from chimera.modules import smoke_test

        state = {
            "domain": "fleet-b.example",
            "server_port": 443,
            "protocol_mode": "reality",
        }
        self._state_file.write_text(json.dumps(state))

        # Мокаем TCP connect = success, TLS handshake = success
        with patch.object(smoke_test, "_STATE_FILE", self._state_file), \
             patch.object(smoke_test, "_tcp_connect",
                          return_value=(True, '')) as mock_tcp, \
             patch.object(smoke_test, "_tls_handshake",
                          return_value=(True, '')) as mock_tls:
            result = smoke_test.smoke_test_xray()
            self.assertTrue(result)
            # Проверяем что _tls_handshake вызван с правильным SNI
            call_args = mock_tls.call_args
            # _tls_handshake(host, port, timeout, sni=...)
            sni_arg = call_args.kwargs.get('sni') or (
                call_args.args[3] if len(call_args.args) > 3 else None)
            self.assertEqual(sni_arg, "fleet-b.example",
                             "SNI должен быть 'fleet-b.example' из state['domain'], "
                             "не 127.0.0.1 (регрессия: state.get('param_domain')=None)")

    def test_xhttp_mode_skips_tls_check(self):
        """xHTTP режим: TLS-проверка пропускается."""
        from chimera.modules import smoke_test

        state = {
            "domain": "example.com",
            "server_port": 443,
            "protocol_mode": "xhttp",
        }
        self._state_file.write_text(json.dumps(state))

        with patch.object(smoke_test, "_STATE_FILE", self._state_file), \
             patch.object(smoke_test, "_tcp_connect",
                          return_value=(True, '')) as mock_tcp, \
             patch.object(smoke_test, "_tls_handshake") as mock_tls:
            result = smoke_test.smoke_test_xray()
            self.assertTrue(result)
            # TLS не должен проверяться в xHTTP режиме
            mock_tls.assert_not_called()

    def test_tcp_failure_returns_false(self):
        """TCP connect failure → return False."""
        from chimera.modules import smoke_test

        state = {"domain": "example.com", "server_port": 443,
                 "protocol_mode": "reality"}
        self._state_file.write_text(json.dumps(state))

        with patch.object(smoke_test, "_STATE_FILE", self._state_file), \
             patch.object(smoke_test, "_tcp_connect",
                          return_value=(False, 'connection refused')), \
             patch("builtins.input", return_value="n"):
            result = smoke_test.smoke_test_xray()
            self.assertFalse(result)

    def test_tls_failure_returns_false(self):
        """TLS handshake failure (not alert) → return False."""
        from chimera.modules import smoke_test

        state = {"domain": "example.com", "server_port": 443,
                 "protocol_mode": "reality"}
        self._state_file.write_text(json.dumps(state))

        with patch.object(smoke_test, "_STATE_FILE", self._state_file), \
             patch.object(smoke_test, "_tcp_connect",
                          return_value=(True, '')), \
             patch.object(smoke_test, "_tls_handshake",
                          return_value=(False, 'timeout 5s')), \
             patch("builtins.input", return_value="n"):
            result = smoke_test.smoke_test_xray()
            self.assertFalse(result)

    def test_custom_port_from_state(self):
        """Порт берётся из state['server_port']."""
        from chimera.modules import smoke_test

        state = {"domain": "example.com", "server_port": 8443,
                 "protocol_mode": "reality"}
        self._state_file.write_text(json.dumps(state))

        with patch.object(smoke_test, "_STATE_FILE", self._state_file), \
             patch.object(smoke_test, "_tcp_connect",
                          return_value=(True, '')) as mock_tcp, \
             patch.object(smoke_test, "_tls_handshake",
                          return_value=(True, '')):
            smoke_test.smoke_test_xray()
            # Проверяем что _tcp_connect вызван с портом 8443
            call_args = mock_tcp.call_args
            port_arg = call_args.args[1]
            self.assertEqual(port_arg, 8443)

    def test_custom_port_override(self):
        """Явно переданный port переопределяет state."""
        from chimera.modules import smoke_test

        state = {"domain": "example.com", "server_port": 443,
                 "protocol_mode": "reality"}
        self._state_file.write_text(json.dumps(state))

        with patch.object(smoke_test, "_STATE_FILE", self._state_file), \
             patch.object(smoke_test, "_tcp_connect",
                          return_value=(True, '')) as mock_tcp, \
             patch.object(smoke_test, "_tls_handshake",
                          return_value=(True, '')):
            smoke_test.smoke_test_xray(port=2053)
            call_args = mock_tcp.call_args
            port_arg = call_args.args[1]
            self.assertEqual(port_arg, 2053)


if __name__ == "__main__":
    unittest.main(verbosity=2)
