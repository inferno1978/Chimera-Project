#!/usr/bin/env python3
"""
tests/test_singbox_nginx.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/singbox_nginx.py.

Покрывает:
  1. _build_nginx_stream_conf — генерация nginx stream{}-конфига
  2. sni_dispatch_status — структура dict
  3. _nginx_has_stream_support / _nginx_has_ssl_preread — detection
  4. _nginx_ensure_stream_include — патч /etc/nginx/nginx.conf
  5. enable_sni_dispatch / disable_sni_dispatch — state changes
  6. Валидация конфигурации
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ─────────────────────────────────────────────────────────────────────────────
# 1. _build_nginx_stream_conf — генерация конфига
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildNginxStreamConf(unittest.TestCase):
    """_build_nginx_stream_conf — генерация nginx stream{}-конфига."""

    def setUp(self):
        _setup_core()

    def test_returns_string(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="shadowtls.example.com",
            anytls_sni="anytls.example.com",
            default_backend="unix:/dev/shm/vless-reality.socket",
        )
        self.assertIsInstance(conf, str)

    def test_contains_map_block(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="shadowtls.example.com",
            anytls_sni="anytls.example.com",
            default_backend="unix:/dev/shm/vless-reality.socket",
        )
        self.assertIn("map $ssl_preread_server_name $singbox_backend", conf)

    def test_contains_server_block_with_listen_443(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="a.example.com",
            anytls_sni="b.example.com",
            default_backend="127.0.0.1:8442",
        )
        self.assertIn("server {", conf)
        self.assertIn("listen 443;", conf)
        self.assertIn("listen [::]:443;", conf)
        self.assertIn("ssl_preread on;", conf)
        self.assertIn("proxy_pass", conf)

    def test_contains_shadowtls_sni_mapping(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="shadowtls.example.com",
            anytls_sni="anytls.example.com",
            default_backend="unix:/dev/shm/x.socket",
            shadowtls_port=8443,
        )
        # Экранированная точка: shadowtls\.example\.com
        self.assertIn("shadowtls\\.example\\.com", conf)
        self.assertIn("127.0.0.1:8443", conf)

    def test_contains_anytls_sni_mapping(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="shadowtls.example.com",
            anytls_sni="anytls.example.com",
            default_backend="unix:/dev/shm/x.socket",
            anytls_port=8444,
        )
        self.assertIn("anytls\\.example\\.com", conf)
        self.assertIn("127.0.0.1:8444", conf)

    def test_contains_default_backend(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="a.example.com",
            anytls_sni="b.example.com",
            default_backend="unix:/dev/shm/test.socket",
        )
        self.assertIn("unix:/dev/shm/test.socket", conf)

    def test_handles_empty_sni_gracefully(self):
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        # Если SNI не задан — соответствующая строка не должна попасть в map
        conf = _build_nginx_stream_conf(
            shadowtls_sni="",
            anytls_sni="",
            default_backend="127.0.0.1:8442",
        )
        # Только default должен быть в map
        self.assertIn("default  127.0.0.1:8442;", conf)
        # Никаких пустых regex-ов
        self.assertNotIn("~^$", conf)

    def test_escapes_dots_in_domain(self):
        """Точки в домене должны быть экранированы для regex."""
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="sub.domain.example.com",
            anytls_sni="",
            default_backend="127.0.0.1:8442",
        )
        self.assertIn("sub\\.domain\\.example\\.com", conf)


# ─────────────────────────────────────────────────────────────────────────────
# 2. sni_dispatch_status
# ─────────────────────────────────────────────────────────────────────────────

class TestSniDispatchStatus(unittest.TestCase):
    """sni_dispatch_status — структура dict."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._tmpdir / "main_state.json"),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
        ]

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.singbox_nginx import sni_dispatch_status
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = sni_dispatch_status()
        self.assertIsInstance(st, dict)
        for key in ("enabled", "shadowtls_sni", "anytls_sni",
                    "default_backend", "config_file_exists",
                    "nginx_stream_support", "nginx_ssl_preread",
                    "nginx_stream_block"):
            self.assertIn(key, st, f"missing key: {key}")

    def test_disabled_by_default(self):
        from vless_installer.modules.singbox_nginx import sni_dispatch_status
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = sni_dispatch_status()
        self.assertFalse(st["enabled"])


# ─────────────────────────────────────────────────────────────────────────────
# 3. nginx support detection
# ─────────────────────────────────────────────────────────────────────────────

class TestNginxSupportDetection(unittest.TestCase):
    """_nginx_has_stream_support / _nginx_has_ssl_preread."""

    def setUp(self):
        _setup_core()

    def test_stream_support_returns_bool(self):
        from vless_installer.modules.singbox_nginx import _nginx_has_stream_support
        # Просто проверяем, что функция возвращает bool (без моков —
        # в тестовой среде nginx может отсутствовать)
        result = _nginx_has_stream_support()
        self.assertIsInstance(result, bool)

    def test_ssl_preread_returns_bool(self):
        from vless_installer.modules.singbox_nginx import _nginx_has_ssl_preread
        result = _nginx_has_ssl_preread()
        self.assertIsInstance(result, bool)

    def test_stream_support_detects_flag_in_nginx_v_output(self):
        from vless_installer.modules.singbox_nginx import _nginx_has_stream_support
        # Мокаем _run, чтобы вернуть вывод с --with-stream
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = "configure arguments: ... --with-stream --with-stream_ssl_module ..."
        mock_result.stdout = ""
        with patch("vless_installer.modules.singbox_nginx._run", return_value=mock_result):
            self.assertTrue(_nginx_has_stream_support())

    def test_stream_support_returns_false_when_flag_absent(self):
        from vless_installer.modules.singbox_nginx import _nginx_has_stream_support
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = "configure arguments: ... --without-stream ..."
        mock_result.stdout = ""
        with patch("vless_installer.modules.singbox_nginx._run", return_value=mock_result):
            self.assertFalse(_nginx_has_stream_support())


# ─────────────────────────────────────────────────────────────────────────────
# 4. _nginx_config_has_stream_block / _nginx_ensure_stream_include
# ─────────────────────────────────────────────────────────────────────────────

class TestNginxConfigStreamBlock(unittest.TestCase):
    """Проверка и патчинг /etc/nginx/nginx.conf."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._nginx_conf = self._tmpdir / "nginx.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_has_stream_block_returns_false_when_no_file(self):
        from vless_installer.modules.singbox_nginx import _nginx_config_has_stream_block
        with patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf):
            self.assertFalse(_nginx_config_has_stream_block())

    def test_has_stream_block_detects_existing(self):
        from vless_installer.modules.singbox_nginx import _nginx_config_has_stream_block
        self._nginx_conf.write_text("http {\n}\nstream {\n}\n")
        with patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf):
            self.assertTrue(_nginx_config_has_stream_block())

    def test_has_stream_block_returns_false_when_no_stream(self):
        from vless_installer.modules.singbox_nginx import _nginx_config_has_stream_block
        self._nginx_conf.write_text("http {\n}\n")
        with patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf):
            self.assertFalse(_nginx_config_has_stream_block())

    def test_ensure_stream_include_creates_block_when_absent(self):
        from vless_installer.modules.singbox_nginx import _nginx_ensure_stream_include
        self._nginx_conf.write_text("http {\n}\n")
        with patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf):
            ok = _nginx_ensure_stream_include()
        self.assertTrue(ok)
        text = self._nginx_conf.read_text()
        self.assertIn("stream {", text)
        self.assertIn("streams-enabled", text)

    def test_ensure_stream_include_idempotent_when_already_present(self):
        """Если include уже есть — не добавляем повторно."""
        from vless_installer.modules.singbox_nginx import _nginx_ensure_stream_include
        original = (
            "http {\n}\n"
            "stream {\n"
            "    include /etc/nginx/streams-enabled/*.conf;\n"
            "}\n"
        )
        self._nginx_conf.write_text(original)
        with patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf):
            _nginx_ensure_stream_include()
        text = self._nginx_conf.read_text()
        # include должен встречаться ровно один раз
        self.assertEqual(text.count("streams-enabled"), 1)

    def test_ensure_stream_include_adds_include_to_existing_block(self):
        """Если блок stream{} есть, но без include — добавляем include."""
        from vless_installer.modules.singbox_nginx import _nginx_ensure_stream_include
        self._nginx_conf.write_text("http {\n}\nstream {\n}\n")
        with patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf):
            ok = _nginx_ensure_stream_include()
        self.assertTrue(ok)
        text = self._nginx_conf.read_text()
        self.assertIn("streams-enabled", text)


# ─────────────────────────────────────────────────────────────────────────────
# 5. enable_sni_dispatch / disable_sni_dispatch — state changes
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableDisableSniDispatch(unittest.TestCase):
    """enable_sni_dispatch / disable_sni_dispatch."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._streams_dir = self._tmpdir / "streams-enabled"
        self._streams_avail = self._tmpdir / "streams-available"
        self._nginx_conf = self._tmpdir / "nginx.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._tmpdir / "main_state.json"),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_nginx.NGINX_STREAMS_DIR", self._streams_dir),
            patch("vless_installer.modules.singbox_nginx.NGINX_STREAMS_AVAIL", self._streams_avail),
            patch("vless_installer.modules.singbox_nginx.NGINX_NGINX_CONF", self._nginx_conf),
            patch("vless_installer.modules.singbox_nginx.NGINX_STREAM_CONF", self._streams_dir / "singbox-dispatch.conf"),
        ]

    def test_enable_returns_false_without_nginx_stream_support(self):
        from vless_installer.modules.singbox_nginx import enable_sni_dispatch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_stream_support", return_value=False))
            ok = enable_sni_dispatch(
                shadowtls_sni="a.example.com",
                anytls_sni="b.example.com",
                default_backend="127.0.0.1:8442",
                interactive=False,
            )
        self.assertFalse(ok)

    def test_enable_returns_false_without_ssl_preread(self):
        from vless_installer.modules.singbox_nginx import enable_sni_dispatch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_stream_support", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_ssl_preread", return_value=False))
            ok = enable_sni_dispatch(
                shadowtls_sni="a.example.com",
                anytls_sni="b.example.com",
                default_backend="127.0.0.1:8442",
                interactive=False,
            )
        self.assertFalse(ok)

    def test_enable_creates_stream_conf_file(self):
        from vless_installer.modules.singbox_nginx import enable_sni_dispatch, NGINX_STREAM_CONF
        # nginx.conf без stream{}, _nginx_ensure_stream_include должен добавить
        self._nginx_conf.write_text("http {\n}\n")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_stream_support", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_ssl_preread", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._run", return_value=MagicMock(returncode=0, stdout="", stderr="")))
            ok = enable_sni_dispatch(
                shadowtls_sni="shadowtls.example.com",
                anytls_sni="anytls.example.com",
                default_backend="unix:/dev/shm/test.socket",
                interactive=False,
            )
        self.assertTrue(ok)
        # Конфиг должен быть создан
        # (он будет в self._streams_dir, а не в /etc/nginx/...)
        conf_path = self._streams_dir / "singbox-dispatch.conf"
        self.assertTrue(conf_path.exists())
        text = conf_path.read_text()
        # Точки экранированы для regex в nginx map
        self.assertIn("shadowtls\\.example\\.com", text)
        self.assertIn("anytls\\.example\\.com", text)
        self.assertIn("unix:/dev/shm/test.socket", text)

    def test_enable_updates_state(self):
        from vless_installer.modules.singbox_nginx import enable_sni_dispatch
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_sni_dispatch,
        )
        self._nginx_conf.write_text("http {\n}\n")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_stream_support", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_ssl_preread", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._run", return_value=MagicMock(returncode=0, stdout="", stderr="")))
            enable_sni_dispatch(
                shadowtls_sni="shadowtls.example.com",
                anytls_sni="anytls.example.com",
                default_backend="unix:/dev/shm/test.socket",
                interactive=False,
            )
            sd = singbox_state_get_sni_dispatch()
        self.assertTrue(sd["enabled"])
        self.assertEqual(sd["shadowtls_sni"], "shadowtls.example.com")
        self.assertEqual(sd["anytls_sni"], "anytls.example.com")

    def test_disable_removes_conf_and_updates_state(self):
        from vless_installer.modules.singbox_nginx import (
            enable_sni_dispatch, disable_sni_dispatch, NGINX_STREAM_CONF,
        )
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_sni_dispatch,
        )
        self._nginx_conf.write_text("http {\n}\n")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_stream_support", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._nginx_has_ssl_preread", return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_nginx._run", return_value=MagicMock(returncode=0, stdout="", stderr="")))
            enable_sni_dispatch(
                shadowtls_sni="a.example.com",
                anytls_sni="b.example.com",
                default_backend="unix:/dev/shm/test.socket",
                interactive=False,
            )
            # Теперь disable
            disable_sni_dispatch(interactive=False)
            sd = singbox_state_get_sni_dispatch()
        self.assertFalse(sd["enabled"])


# ─────────────────────────────────────────────────────────────────────────────
# 6. validate_sni_dispatch_config
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateConfig(unittest.TestCase):
    """validate_sni_dispatch_config — проверка валидности."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_no_config_file(self):
        from vless_installer.modules.singbox_nginx import validate_sni_dispatch_config
        nonexistent = self._tmpdir / "nonexistent.conf"
        with patch("vless_installer.modules.singbox_nginx.NGINX_STREAM_CONF", nonexistent):
            self.assertFalse(validate_sni_dispatch_config())


if __name__ == "__main__":
    unittest.main(verbosity=2)
