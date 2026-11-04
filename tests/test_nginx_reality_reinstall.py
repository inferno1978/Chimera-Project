#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# tests/test_nginx_reality_reinstall.py
# Регресс-тесты реинсталл-безопасности REALITY+Unix-сокет (репорт 04.11):
# повторная установка chimera поверх РАБОТАЮЩЕГО VLESS REALITY-сервера
# не должна рвать fallback (unlink действующего сокета / stop nginx).
from __future__ import annotations

import shutil
import socket as sock_mod
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class _LiveUnixServer:
    # Реальный слушающий unix-сокет в коротком tmp-пути (sun_path < 108).
    def __init__(self, path):
        self.path = path
        self.srv = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        self.srv.bind(str(path))
        self.srv.listen(8)

    def close(self):
        try:
            self.srv.close()
        except Exception:
            pass
        try:
            self.path.unlink()
        except Exception:
            pass


def _make_fake_core(tmpdir, sock_path, nginx_t_rc=0, nginx_active=True):
    core = types.ModuleType('chimera._core')
    core.info = lambda *a, **k: None
    core.success = lambda *a, **k: None
    core.warn = lambda *a, **k: None
    core.log_to_file = lambda *a, **k: None
    core.find_nginx_bin = lambda: '/usr/sbin/nginx'
    core.PROTOCOL_MODE = 'reality'
    core.AWG_EXIT_ENABLED = False
    core.PARAM_DOMAIN = 'vless.example.com'
    core.PARAM_SOCKET_PATH = str(sock_path)
    core.SERVER_PORT = 443
    core.XHTTP_BACKEND_PORT = 8443
    core.XHTTP_PATH = '/xhttp'
    core.IS_IPV6_AVAILABLE = False
    core.NGINX_CONF_DIR = tmpdir / 'conf'
    core.NGINX_ENABLED_DIR = tmpdir / 'enabled'
    core.NGINX_RATE_LIMIT_CONF = tmpdir / 'no_rate_limit'
    calls = []

    def _run(cmd, **kw):
        calls.append(list(cmd))
        r = MagicMock()
        r.returncode = 0
        r.stdout = ''
        r.stderr = 'nginx version: nginx/1.25.3\n'
        if list(cmd[:2]) == ['systemctl', 'is-active']:
            r.stdout = 'active\n' if nginx_active else 'inactive\n'
        elif len(cmd) == 2 and cmd[1] == '-t':
            r.returncode = nginx_t_rc
            r.stderr = ''
        return r

    core._run = _run
    return core, calls


class TestUnixSocketServing(unittest.TestCase):
    # 1. Проба живости: listening в /proc/net/unix; плейсхолдер/файла-нет → False.

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix='nrr_probe_'))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_listening_socket_is_serving(self):
        from chimera.modules.nginx_setup import _unix_socket_serving
        srv = _LiveUnixServer(self._tmp / 'live.sock')
        try:
            self.assertTrue(_unix_socket_serving(self._tmp / 'live.sock'))
        finally:
            srv.close()

    def test_placeholder_and_missing_are_not_serving(self):
        from chimera.modules.nginx_setup import _unix_socket_serving
        p = self._tmp / 'dead.sock'
        s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        s.bind(str(p))
        s.close()
        self.assertTrue(p.exists())
        self.assertFalse(_unix_socket_serving(p))
        self.assertFalse(_unix_socket_serving(self._tmp / 'nope.sock'))


class _SetupNginxFinalBase(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix='nrr_run_'))
        self._sock = self._tmp / 's.sock'
        self._saved_core = sys.modules.get('chimera._core')

    def tearDown(self):
        if self._saved_core is not None:
            sys.modules['chimera._core'] = self._saved_core
        else:
            sys.modules.pop('chimera._core', None)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run_setup(self, nginx_t_rc=0, nginx_active=True):
        from chimera.modules import nginx_setup
        core, calls = _make_fake_core(self._tmp, self._sock,
                                      nginx_t_rc=nginx_t_rc,
                                      nginx_active=nginx_active)
        sys.modules['chimera._core'] = core
        with patch.object(nginx_setup, 'create_website', lambda **kw: None):
            nginx_setup.setup_nginx_final()
        return calls


class TestReinstallSafety(_SetupNginxFinalBase):
    # 2. Живой сокет: не удаляем, не стопим nginx, reload выполнен.
    def test_reinstall_keeps_live_socket(self):
        srv = _LiveUnixServer(self._sock)
        try:
            calls = self._run_setup()
            self.assertIn(['systemctl', 'reload', 'nginx'], calls)
            self.assertNotIn(['systemctl', 'stop', 'nginx'], calls)
            self.assertNotIn(['systemctl', 'restart', 'nginx'], calls)
            from chimera.modules.nginx_setup import _unix_socket_serving
            self.assertTrue(self._sock.exists())
            self.assertTrue(_unix_socket_serving(self._sock))
        finally:
            srv.close()

    # 3. Fresh: плейсхолдер снесён, stop nginx вызван (канон fresh-флоу).
    def test_fresh_install_unlinks_placeholder_and_stops(self):
        calls = self._run_setup()
        self.assertIn(['systemctl', 'reload', 'nginx'], calls)
        self.assertIn(['systemctl', 'stop', 'nginx'], calls)
        self.assertFalse(self._sock.exists())

    # 4. Stale-плейсхолдер (файл есть, никто не слушает): снесён, stop вызван.
    def test_stale_placeholder_cleaned_up(self):
        s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        s.bind(str(self._sock))
        s.close()
        self.assertTrue(self._sock.exists())
        calls = self._run_setup()
        self.assertIn(['systemctl', 'stop', 'nginx'], calls)
        self.assertFalse(self._sock.exists())

    # 5. nginx -t провалился на живом сервере: ничего не трогаем.
    def test_nginx_t_fail_on_live_server_keeps_everything(self):
        srv = _LiveUnixServer(self._sock)
        try:
            calls = self._run_setup(nginx_t_rc=1)
            self.assertNotIn(['systemctl', 'stop', 'nginx'], calls)
            self.assertNotIn(['systemctl', 'restart', 'nginx'], calls)
            self.assertNotIn(['systemctl', 'reload', 'nginx'], calls)
            self.assertTrue(self._sock.exists())
            from chimera.modules.nginx_setup import _unix_socket_serving
            self.assertTrue(_unix_socket_serving(self._sock))
        finally:
            srv.close()

    # 6. Пост-чек heals: сокет пропал после reload → restart nginx + ожидание.
    def test_postcheck_heals_disappeared_socket(self):
        from chimera.modules import nginx_setup
        core, calls = _make_fake_core(self._tmp, self._sock)
        sys.modules['chimera._core'] = core
        probe_states = iter([True, False, True])
        with patch.object(nginx_setup, 'create_website', lambda **kw: None), \
             patch.object(nginx_setup, '_unix_socket_serving',
                          lambda p: next(probe_states)), \
             patch.object(nginx_setup.time, 'sleep', lambda s: None):
            nginx_setup.setup_nginx_final()
        self.assertIn(['systemctl', 'restart', 'nginx'], calls)
        self.assertNotIn(['systemctl', 'stop', 'nginx'], calls)

    # 7. nginx не active + сокет не живой (dead-флоу): stop вызван —
    #    финальный шаг установки поднимет nginx до xray.
    def test_nginx_inactive_dead_socket_stops_nginx(self):
        calls = self._run_setup(nginx_active=False)
        self.assertIn(['systemctl', 'stop', 'nginx'], calls)
        self.assertNotIn(['systemctl', 'reload', 'nginx'], calls)
        self.assertFalse(self._sock.exists())


if __name__ == '__main__':
    unittest.main()
