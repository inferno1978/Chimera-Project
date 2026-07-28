#!/usr/bin/env python3
"""
tests/test_nginx_cdn_masking_config.py
───────────────────────────────────────────────────────────────────────────────
Регрессионный тест на багу «large_client_header_buffers directive is not
allowed here» в CDN masking профиле.

Бага: директива large_client_header_buffers была вставлена в location {}
блок, но согласно документации nginx она допустима только в http {} контексте.
Nginx падал с emerg при запуске:
    "large_client_header_buffers" directive is not allowed here in
    /etc/nginx/sites-enabled/<domain>:63

Тестируется статическим анализом исходника setup_nginx_final() —
проверяем, что:
  1. _cdn_server_extras содержит large_client_header_buffers + underscore_in_headers
  2. _cdn_location_extras НЕ содержит эти директивы (они не для location)
  3. {_cdn_server_extras} подставляется в server-блок (после add_header)
  4. {_cdn_location_extras} подставляется в location-блок
  5. старая переменная _cdn_extras удалена
"""
from __future__ import annotations

import inspect
import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestNginxCdnMaskingConfigContext(unittest.TestCase):
    """CDN masking: nginx-директивы в правильных контекстах (server vs location).

    Регрессия на багу «large_client_header_buffers directive is not allowed here».
    """

    def setUp(self):
        from chimera.modules import nginx_setup
        self._src = inspect.getsource(nginx_setup.setup_nginx_final)

    def test_cdn_server_extras_variable_exists(self):
        """Переменная _cdn_server_extras определена в setup_nginx_final."""
        self.assertIn("_cdn_server_extras", self._src,
            "_cdn_server_extras variable must be defined in setup_nginx_final")

    def test_cdn_location_extras_variable_exists(self):
        """Переменная _cdn_location_extras определена в setup_nginx_final."""
        self.assertIn("_cdn_location_extras", self._src,
            "_cdn_location_extras variable must be defined in setup_nginx_final")

    def test_old_cdn_extras_variable_removed(self):
        """Старая переменная _cdn_extras удалена (она была в location — бага)."""
        # Убираем новые имена, проверяем что старого нет
        src_cleaned = self._src.replace("_cdn_server_extras", "").replace("_cdn_location_extras", "")
        self.assertNotIn("_cdn_extras", src_cleaned,
            "Old _cdn_extras variable must be removed — it caused "
            "large_client_header_buffers to be in location block")

    def test_large_client_header_buffers_in_server_block(self):
        """large_client_header_buffers в _cdn_server_extras (server context).

        Согласно документации nginx:
            Context: http
        Location не подходит → была бага с emerg при запуске nginx.
        """
        m = re.search(r'_cdn_server_extras\s*=\s*textwrap\.dedent\(f?"""(.*?)"""',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m, "Could not find _cdn_server_extras assignment")
        server_block = m.group(1)
        self.assertIn("large_client_header_buffers", server_block,
            "large_client_header_buffers must be in _cdn_server_extras (server context)")

    def test_underscore_in_headers_in_server_block(self):
        """underscore_in_headers в _cdn_server_extras (server context).

        Согласно документации nginx:
            Context: http, server
        Location не подходит.
        """
        m = re.search(r'_cdn_server_extras\s*=\s*textwrap\.dedent\(f?"""(.*?)"""',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        server_block = m.group(1)
        self.assertIn("underscore_in_headers", server_block,
            "underscore_in_headers must be in _cdn_server_extras (server context)")

    def test_large_client_header_buffers_NOT_in_location_block(self):
        """large_client_header_buffers ОТСУТСТВУЕТ в _cdn_location_extras.

        Регрессия: раньше был в location → nginx emerg.
        """
        m = re.search(r'_cdn_location_extras\s*=\s*textwrap\.dedent\(f?"""(.*?)"""',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m, "Could not find _cdn_location_extras assignment")
        location_block = m.group(1)
        self.assertNotIn("large_client_header_buffers", location_block,
            "large_client_header_buffers MUST NOT be in _cdn_location_extras "
            "(nginx: 'directive is not allowed here' in location context)")

    def test_underscore_in_headers_NOT_in_location_block(self):
        """underscore_in_headers ОТСУТСТВУЕТ в _cdn_location_extras."""
        m = re.search(r'_cdn_location_extras\s*=\s*textwrap\.dedent\(f?"""(.*?)"""',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        location_block = m.group(1)
        self.assertNotIn("underscore_in_headers", location_block,
            "underscore_in_headers MUST NOT be in _cdn_location_extras")

    def test_location_safe_directives_in_location_block(self):
        """proxy_* директивы в _cdn_location_extras (они допустимы в location).

        Согласно документации nginx:
            proxy_send_timeout:       Context: http, server, location
            proxy_read_timeout:       Context: http, server, location
            proxy_next_upstream:      Context: http, server, location
            proxy_next_upstream_tries: Context: http, server, location
        """
        m = re.search(r'_cdn_location_extras\s*=\s*textwrap\.dedent\(f?"""(.*?)"""',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        location_block = m.group(1)
        self.assertIn("proxy_send_timeout", location_block,
            "proxy_send_timeout should be in location block (it's location-safe)")
        self.assertIn("proxy_read_timeout", location_block,
            "proxy_read_timeout should be in location block")
        self.assertIn("proxy_next_upstream", location_block,
            "proxy_next_upstream should be in location block")

    def test_server_extras_placeholder_in_server_context(self):
        """{_cdn_server_extras} подставляется в server-блок, не в location.

        Проверяем порядок: add_header X-Robots-Tag → {_cdn_server_extras} → location.
        """
        add_header_pos = self._src.find("add_header X-Robots-Tag")
        server_extras_pos = self._src.find("{_cdn_server_extras}")
        location_pos = self._src.find("location {_xhttp_path}")
        self.assertGreater(add_header_pos, 0, "add_header X-Robots-Tag not found")
        self.assertGreater(server_extras_pos, 0, "{_cdn_server_extras} placeholder not found")
        self.assertGreater(location_pos, 0, "location {_xhttp_path} not found")
        self.assertLess(add_header_pos, server_extras_pos,
            "{_cdn_server_extras} must come AFTER add_header (in server block)")
        self.assertLess(server_extras_pos, location_pos,
            "{_cdn_server_extras} must come BEFORE location (it's server-level)")

    def test_location_extras_placeholder_in_location_context(self):
        """{_cdn_location_extras} подставляется в location-блок."""
        location_pos = self._src.find("location {_xhttp_path}")
        location_extras_pos = self._src.find("{_cdn_location_extras}")
        self.assertGreater(location_pos, 0)
        self.assertGreater(location_extras_pos, 0)
        self.assertLess(location_pos, location_extras_pos,
            "{_cdn_location_extras} must come AFTER location (it's location-level)")


if __name__ == "__main__":
    unittest.main()
