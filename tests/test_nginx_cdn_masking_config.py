#!/usr/bin/env python3
"""
tests/test_nginx_cdn_masking_config.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты на баги в CDN masking профиле nginx-конфига:

1. «large_client_header_buffers directive is not allowed here» (коммит 1b434e3)
   — директива была в location {} блоке.

2. «unknown directive underscores_in_headers» (коммиты fcb0cab, 648aebc)
   — изначально объяснялось "кастомной сборкой nginx без core-модуля"
     (fcb0cab), потом "сломанными отступами от textwrap.dedent" (648aebc).
     Оба объяснения были НЕВЕРНЫМИ. Реальная причина: ОПЕЧАТКА в имени
     директивы — правильно "underscores_in_headers" (с "s", множественное
     число), а в коде было "underscores_in_headers" (без "s"). nginx не
     знает директивы "underscores_in_headers" вообще ни в каком контексте.
     Эти тесты тоже содержали опечатку и не могли её поймать — пока
     пользователь не проверил на реальном nginx/1.24.0.

3. Дублирование proxy_send_timeout/proxy_read_timeout в location-блоке
   — безусловная часть location содержала proxy_*_timeout 3600s,
     а _cdn_location_extras повторно объявлял их с 86400s → nginx падал
     с "duplicate directive".

Тестируется через:
  • Статический анализ исходника setup_nginx_final() (через inspect.getsource).
  • Генерацию реального vhost-файла и анализ его содержимого.
  • Подсчёт вхождений директив (дублирование = бага).

ВАЖНО: nginx -t физически не прогоняется в тестовой среде (нет root-прав
для установки nginx). Тесты проверяют структуру конфига статически.
Реальная проверка nginx -t должна выполняться на живом сервере.
"""
from __future__ import annotations

import inspect
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py через exec и регистрирует фейк в sys.modules."""
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


def _generate_vhost(cdn_masking_mode: bool) -> str:
    """Генерирует реальный vhost-файл через setup_nginx_final() и возвращает содержимое.

    Мокает /var/www через перенаправление в temp-каталог.
    ВАЖНО: сохраняет и восстанавливает sys.modules["chimera._core"] чтобы
    не влиять на другие тесты (test_cdn_masking_guide и др.).
    """
    # Сохраняем оригинальный chimera._core из sys.modules (если уже загружен).
    # НЕ импортируем напрямую — это может вызвать побочные эффекты (mkdir и т.п.).
    _orig_core_in_sys = sys.modules.get("chimera._core")

    core = _setup_core_in_sysmodules()
    tmpdir = Path(tempfile.mkdtemp(prefix="nginx_test_"))
    nginx_conf_dir = tmpdir / "nginx-conf"
    nginx_conf_dir.mkdir(parents=True, exist_ok=True)
    enabled_dir = tmpdir / "enabled"
    enabled_dir.mkdir(parents=True, exist_ok=True)

    core.PROTOCOL_MODE = "xhttp"
    core.XHTTP_PATH = "/api/v2/static.ts"
    core.XHTTP_BACKEND_PORT = 7443 if cdn_masking_mode else 8443
    core.PARAM_DOMAIN = "test.example.com"
    core.PARAM_SOCKET_PATH = "/run/xray.sock"
    core.AWG_EXIT_ENABLED = False
    core.IS_IPV6_AVAILABLE = False
    core.SERVER_PORT = 443
    core.PARAM_SITE_TEMPLATE = "16" if cdn_masking_mode else "2"
    core.NGINX_CONF_DIR = nginx_conf_dir
    core.NGINX_ENABLED_DIR = enabled_dir
    core.NGINX_RATE_LIMIT_CONF = tmpdir / "rate.conf"
    core._run = MagicMock(return_value=MagicMock(returncode=0, stdout="",
                                                   stderr="nginx version"))
    core.find_nginx_bin = lambda: "/usr/sbin/nginx"
    core.info = lambda *a, **kw: None
    core.warn = lambda *a, **kw: None
    core.success = lambda *a, **kw: None
    core.log_to_file = lambda *a, **kw: None

    # Patch create_website / create_fake_login чтобы не писать в /var/www
    import chimera.modules.nginx_setup_templates as nst
    _orig_fake_login = getattr(nst, "create_fake_login", None)
    nst.create_fake_login = lambda web_root: None
    import chimera.modules.nginx_setup as ns
    _orig_create_website = ns.create_website
    ns.create_website = lambda **kw: None

    # Redirect /var/www → tmpdir
    tmpdir_str = str(tmpdir)
    orig_mkdir = Path.mkdir
    def patched_mkdir(self, *args, **kwargs):
        s = str(self)
        if s.startswith("/var/www/"):
            self = Path(tmpdir_str + s[len("/var/www"):])
        return orig_mkdir(self, *args, **kwargs)
    Path.mkdir = patched_mkdir

    orig_write_text = Path.write_text
    def patched_write_text(self, data, *args, **kwargs):
        s = str(self)
        if s.startswith("/var/www/"):
            new_path = Path(tmpdir_str + s[len("/var/www"):])
            new_path.parent.mkdir(parents=True, exist_ok=True)
            return orig_write_text(new_path, data, *args, **kwargs)
        return orig_write_text(self, data, *args, **kwargs)
    Path.write_text = patched_write_text

    orig_exists = Path.exists
    def patched_exists(self, *args, **kwargs):
        s = str(self)
        if s.startswith("/var/www/"):
            new_path = Path(tmpdir_str + s[len("/var/www"):])
            return orig_exists(new_path, *args, **kwargs)
        return orig_exists(self, *args, **kwargs)
    Path.exists = patched_exists

    orig_symlink = Path.symlink_to
    Path.symlink_to = lambda self, target, *a, **kw: orig_symlink(self, target, *a, **kw)

    try:
        ns.setup_nginx_final(cdn_masking_mode=cdn_masking_mode)
    finally:
        # Восстанавливаем ВСЁ
        Path.mkdir = orig_mkdir
        Path.write_text = orig_write_text
        Path.exists = orig_exists
        Path.symlink_to = orig_symlink
        ns.create_website = _orig_create_website
        if _orig_fake_login is not None:
            nst.create_fake_login = _orig_fake_login
        # Восстанавливаем оригинальный chimera._core
        if _orig_core_in_sys is not None:
            sys.modules["chimera._core"] = _orig_core_in_sys

    vhost_file = nginx_conf_dir / "test.example.com"
    if not vhost_file.exists():
        raise RuntimeError(f"vhost file not generated: {vhost_file}")
    return vhost_file.read_text()


def _count_in_location(content: str, directive: str) -> int:
    """Подсчитывает вхождения директивы в location-блоках."""
    lines = content.split('\n')
    in_location = False
    loc_depth = 0
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('location ') and '{' in stripped:
            in_location = True
            loc_depth = stripped.count('{') - stripped.count('}')
            continue
        if in_location:
            if '{' in stripped: loc_depth += stripped.count('{')
            if '}' in stripped:
                loc_depth -= stripped.count('}')
                if loc_depth <= 0:
                    in_location = False
                    continue
            if stripped.startswith(directive):
                count += 1
    return count


def _count_in_server(content: str, directive: str) -> int:
    """Подсчитывает вхождения директивы в server-блоках (но не в location)."""
    lines = content.split('\n')
    in_server = False
    in_location = False
    server_depth = 0
    loc_depth = 0
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('server ') and '{' in stripped and not in_server:
            in_server = True
            server_depth = stripped.count('{') - stripped.count('}')
            continue
        if in_server:
            if stripped.startswith('location ') and '{' in stripped:
                in_location = True
                loc_depth = stripped.count('{') - stripped.count('}')
                continue
            if in_location:
                if '{' in stripped: loc_depth += stripped.count('{')
                if '}' in stripped:
                    loc_depth -= stripped.count('}')
                    if loc_depth <= 0:
                        in_location = False
                continue
            if '{' in stripped: server_depth += stripped.count('{')
            if '}' in stripped:
                server_depth -= stripped.count('}')
                if server_depth <= 0:
                    in_server = False
                continue
            if stripped.startswith(directive):
                count += 1
    return count


class TestNginxCdnMaskingConfigContext(unittest.TestCase):
    """CDN masking: nginx-директивы в правильных контекстах и без дублирования.

    Регрессия на три бага:
      1. «large_client_header_buffers directive is not allowed here» (1b434e3)
      2. «unknown directive underscores_in_headers» (fcb0cab — неверное объяснение)
      3. Дублирование proxy_*_timeout в location-блоке
    """

    def setUp(self):
        from chimera.modules import nginx_setup
        self._src = inspect.getsource(nginx_setup.setup_nginx_final)

    # ── ЧАСТЬ 1: underscores_in_headers возвращён ──────────────────────────

    def test_underscores_in_headers_present_in_source(self):
        """underscores_in_headers присутствует в _cdn_server_extras (возвращена).

        Регрессия на fcb0cab: директива была убрана с неверным объяснением
        "кастомная сборка nginx без core-модуля". Реальная причина была в
        сломанных отступах от textwrap.dedent(). Директива возвращена.
        """
        self.assertIn("underscores_in_headers", self._src,
            "underscores_in_headers must be present in setup_nginx_final — "
            "it was incorrectly removed in fcb0cab due to misdiagnosed cause")

    def test_underscores_in_headers_in_server_extras(self):
        """underscores_in_headers в _cdn_server_extras (server context).

        Согласно документации nginx: Context: http, server (НЕ location).
        """
        # Ищем блок _cdn_server_extras = ...
        m = re.search(r'_cdn_server_extras\s*=\s*\((.*?)\)',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m, "Could not find _cdn_server_extras assignment")
        server_block = m.group(1)
        self.assertIn("underscores_in_headers", server_block,
            "underscores_in_headers must be in _cdn_server_extras (server context)")

    def test_underscores_in_headers_NOT_in_location_extras(self):
        """underscores_in_headers ОТСУТСТВУЕТ в _cdn_location_extras."""
        m = re.search(r'_cdn_location_extras\s*=\s*\((.*?)\)',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        location_block = m.group(1)
        self.assertNotIn("underscores_in_headers", location_block,
            "underscores_in_headers MUST NOT be in _cdn_location_extras")

    def test_large_client_header_buffers_in_server_extras(self):
        """large_client_header_buffers в _cdn_server_extras (server context)."""
        m = re.search(r'_cdn_server_extras\s*=\s*\((.*?)\)',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        server_block = m.group(1)
        self.assertIn("large_client_header_buffers", server_block)

    def test_large_client_header_buffers_NOT_in_location_extras(self):
        """large_client_header_buffers ОТСУТСТВУЕТ в _cdn_location_extras."""
        m = re.search(r'_cdn_location_extras\s*=\s*\((.*?)\)',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        location_block = m.group(1)
        self.assertNotIn("large_client_header_buffers", location_block)

    def test_no_textwrap_dedent_in_cdn_extras(self):
        """textwrap.dedent() НЕ используется для _cdn_*_extras.

        Регрессия: textwrap.dedent() ломал отступы при вставке в f-string —
        директива оказывалась в column 0, nginx терял контекст server{}.
        Теперь используются явные строки с правильными отступами.
        """
        # Находим блок с _cdn_server_extras и _cdn_location_extras
        m = re.search(r'(_cdn_server_extras\s*=\s*.*?_cdn_location_extras\s*=\s*.*?\))',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        block = m.group(1)
        self.assertNotIn("textwrap.dedent", block,
            "textwrap.dedent() must NOT be used for _cdn_*_extras — "
            "it breaks indentation when embedded in f-string. "
            "Use explicit strings with proper indentation instead.")

    # ── ЧАСТЬ 2: дублирование proxy_*_timeout устранено ───────────────────

    def test_proxy_timeout_variable_exists(self):
        """Переменная _proxy_timeout определена (устраняет дублирование)."""
        self.assertIn("_proxy_timeout", self._src,
            "_proxy_timeout variable must be defined to avoid duplication "
            "of proxy_read_timeout/proxy_send_timeout in location block")

    def test_proxy_timeout_value_cdn_masking(self):
        """_proxy_timeout = '86400s' при cdn_masking_mode=True."""
        self.assertIn('"86400s" if cdn_masking_mode', self._src,
            "_proxy_timeout must be '86400s' when cdn_masking_mode=True")

    def test_proxy_timeout_value_simple(self):
        """_proxy_timeout = '3600s' при cdn_masking_mode=False."""
        self.assertIn('else "3600s"', self._src,
            "_proxy_timeout must be '3600s' when cdn_masking_mode=False")

    def test_proxy_read_send_timeout_not_in_cdn_location_extras(self):
        """proxy_read_timeout/proxy_send_timeout УБРАНЫ из _cdn_location_extras.

        Регрессия: раньше они дублировались — 3600s в безусловной части
        location + 86400s в _cdn_location_extras → nginx "duplicate directive".
        """
        m = re.search(r'_cdn_location_extras\s*=\s*\((.*?)\)',
                       self._src, re.DOTALL)
        self.assertIsNotNone(m)
        location_block = m.group(1)
        self.assertNotIn("proxy_read_timeout", location_block,
            "proxy_read_timeout MUST NOT be in _cdn_location_extras — "
            "it's now in the unconditional part via _proxy_timeout variable")
        self.assertNotIn("proxy_send_timeout", location_block,
            "proxy_send_timeout MUST NOT be in _cdn_location_extras — "
            "it's now in the unconditional part via _proxy_timeout variable")

    # ── Интеграционные тесты: генерация реального vhost ────────────────────

    def test_cdn_vhost_has_no_duplicate_proxy_timeout_in_location(self):
        """CDN masking vhost: proxy_read_timeout ровно 1 раз в location.

        Регрессия: раньше было 2 (3600s + 86400s) → nginx "duplicate directive".
        """
        content = _generate_vhost(cdn_masking_mode=True)
        count_read = _count_in_location(content, "proxy_read_timeout")
        count_send = _count_in_location(content, "proxy_send_timeout")
        self.assertEqual(count_read, 1,
            f"proxy_read_timeout must appear exactly 1 time in location, "
            f"got {count_read} (duplication = nginx duplicate directive error)")
        self.assertEqual(count_send, 1,
            f"proxy_send_timeout must appear exactly 1 time in location, "
            f"got {count_send}")

    def test_cdn_vhost_proxy_timeout_is_86400s(self):
        """CDN masking vhost: proxy_*_timeout = 86400s (24h for CDN)."""
        content = _generate_vhost(cdn_masking_mode=True)
        self.assertIn("proxy_read_timeout 86400s", content,
            "CDN masking: proxy_read_timeout must be 86400s (24h)")
        self.assertIn("proxy_send_timeout 86400s", content,
            "CDN masking: proxy_send_timeout must be 86400s (24h)")
        # Не должно быть 3600s в CDN masking режиме
        self.assertNotIn("proxy_read_timeout 3600s", content,
            "CDN masking: 3600s must NOT appear (should be 86400s)")

    def test_simple_vhost_proxy_timeout_is_3600s(self):
        """Simple XHTTP vhost: proxy_*_timeout = 3600s (1h, без CDN)."""
        content = _generate_vhost(cdn_masking_mode=False)
        self.assertIn("proxy_read_timeout 3600s", content)
        self.assertIn("proxy_send_timeout 3600s", content)
        self.assertNotIn("proxy_read_timeout 86400s", content,
            "Simple XHTTP: 86400s must NOT appear (should be 3600s)")

    def test_simple_vhost_has_no_duplicate_proxy_timeout_in_location(self):
        """Simple XHTTP vhost: proxy_*_timeout ровно 1 раз в location."""
        content = _generate_vhost(cdn_masking_mode=False)
        count_read = _count_in_location(content, "proxy_read_timeout")
        count_send = _count_in_location(content, "proxy_send_timeout")
        self.assertEqual(count_read, 1,
            f"Simple XHTTP: proxy_read_timeout must be 1, got {count_read}")
        self.assertEqual(count_send, 1,
            f"Simple XHTTP: proxy_send_timeout must be 1, got {count_send}")

    def test_cdn_vhost_has_underscores_in_headers_with_proper_indent(self):
        """CDN vhost: underscores_in_headers есть и с правильным отступом.

        Регрессия на fcb0cab: директива была убрана. Также проверяем,
        что отступ правильный (4+ пробела = server-уровень), а не column 0.
        """
        content = _generate_vhost(cdn_masking_mode=True)
        lines = content.split('\n')
        found = False
        for i, line in enumerate(lines, 1):
            if 'underscores_in_headers' in line and not line.strip().startswith('#'):
                found = True
                # Должна иметь отступ (не в column 0)
                self.assertTrue(line.startswith('    ') or line.startswith('\t'),
                    f"L{i}: underscores_in_headers must have indent (server-level), "
                    f"got: {line!r}")
        self.assertTrue(found,
            "underscores_in_headers must be present in CDN masking vhost")

    def test_cdn_vhost_has_large_client_header_buffers_with_proper_indent(self):
        """CDN vhost: large_client_header_buffers с правильным отступом."""
        content = _generate_vhost(cdn_masking_mode=True)
        lines = content.split('\n')
        found = False
        for i, line in enumerate(lines, 1):
            if 'large_client_header_buffers' in line and not line.strip().startswith('#'):
                found = True
                self.assertTrue(line.startswith('    ') or line.startswith('\t'),
                    f"L{i}: large_client_header_buffers must have indent, "
                    f"got: {line!r}")
        self.assertTrue(found)

    def test_cdn_vhost_braces_balanced(self):
        """CDN vhost: скобки { и } сбалансированы."""
        content = _generate_vhost(cdn_masking_mode=True)
        opens = content.count('{')
        closes = content.count('}')
        self.assertEqual(opens, closes,
            f"Braces unbalanced: {{ = {opens}, }} = {closes}")

    def test_simple_vhost_braces_balanced(self):
        """Simple vhost: скобки { и } сбалансированы."""
        content = _generate_vhost(cdn_masking_mode=False)
        opens = content.count('{')
        closes = content.count('}')
        self.assertEqual(opens, closes,
            f"Braces unbalanced: {{ = {opens}, }} = {closes}")

    def test_cdn_vhost_all_directives_end_with_semicolon(self):
        """CDN vhost: все директивы заканчиваются на ; (кроме строк с { })."""
        content = _generate_vhost(cdn_masking_mode=True)
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if '{' in stripped or '}' in stripped:
                continue
            # Директива должна заканчиваться на ;
            if re.match(r'^[a-z_]+', stripped) and not stripped.endswith(';') and not stripped.endswith('}'):
                self.fail(f"L{i}: directive without semicolon: {stripped!r}")

    def test_simple_vhost_no_cdn_extras(self):
        """Simple vhost: нет CDN-masking директив (large_client_header_buffers и др.)."""
        content = _generate_vhost(cdn_masking_mode=False)
        self.assertNotIn("large_client_header_buffers", content,
            "Simple XHTTP vhost must NOT have large_client_header_buffers")
        self.assertNotIn("underscores_in_headers", content,
            "Simple XHTTP vhost must NOT have underscores_in_headers")
        self.assertNotIn("proxy_next_upstream off", content,
            "Simple XHTTP vhost must NOT have proxy_next_upstream off")


if __name__ == "__main__":
    unittest.main()
