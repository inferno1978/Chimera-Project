#!/usr/bin/env python3
"""
tests/test_xray_install.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/xray_install.py — установка/обновление
Xray-core, парсинг x25519-ключей, нормализация версий, поиск конфигов,
генерация systemd-unit, проверка SHA256.

Покрывает (только чистую логику, без реальной сети/subprocess):
  1. _parse_x25519_keys — парсинг вывода `xray x25519` (старый и новый формат v26+).
  2. _parse_x25519_field — regex-поиск поля в multi-line выводе.
  3. _xray_version_norm — нормализация версии в лексикографически-сравнимую строку.
  4. _xray_find_config — поиск config.json в стандартных локациях.
  5. _xray_current_version — парсинг версии из `xray version` (mocked _run).
  6. _xray_get_release_info — парсинг GitHub API (mocked _run).
  7. _detect_xhttp_mode_support — определение date-based vs семантической версии.
  8. _verify_sha256 — верификация SHA256 (mocked _run, command_exists).
  9. create_xray_service — генерация systemd-unit (3 ветки: xhttp / AWG / REALITY).
"""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py через exec и регистрирует фейк в sys.modules.

    Паттерн из tests/test_health.py (эталон): Path.mkdir/touch/chmod,
    os.chown, os.geteuid — патчатся, чтобы код _core.py не падал.
    """
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core
    return fake_core


# ══════════════════════════════════════════════════════════════════════════════
#  _parse_x25519_keys — парсинг вывода `xray x25519`
# ══════════════════════════════════════════════════════════════════════════════
class TestParseX25519Keys(unittest.TestCase):
    """_parse_x25519_keys: корректный парсинг для всех версий Xray."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_old_format_private_public(self):
        """Старый формат Xray <v26: 'Private key: xxx\\nPublic key: yyy'."""
        from vless_installer.modules.xray_install import _parse_x25519_keys
        output = (
            "Private key: abc123DEF456\n"
            "Public key:  XYZ789ghi012\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "abc123DEF456")
        self.assertEqual(pub, "XYZ789ghi012")

    def test_new_format_v26_password(self):
        """Новый формат Xray v26+: 'Password: xxx' (это public key)."""
        from vless_installer.modules.xray_install import _parse_x25519_keys
        output = (
            "Password: v2.6-public-key-here\n"
            "Private key: v2.6-private-key-here\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "v2.6-private-key-here")
        self.assertEqual(pub, "v2.6-public-key-here")

    def test_returns_empty_for_empty_output(self):
        from vless_installer.modules.xray_install import _parse_x25519_keys
        priv, pub = _parse_x25519_keys("")
        self.assertEqual(priv, "")
        self.assertEqual(pub, "")

    def test_returns_empty_for_garbage(self):
        from vless_installer.modules.xray_install import _parse_x25519_keys
        priv, pub = _parse_x25519_keys("hello\nworld\nfoo bar baz")
        self.assertEqual(priv, "")
        self.assertEqual(pub, "")

    def test_skips_lines_without_colon(self):
        """Строки без ':' пропускаются."""
        from vless_installer.modules.xray_install import _parse_x25519_keys
        output = (
            "some random line without colon\n"
            "Private key: thepriv\n"
            "another random line\n"
            "Public key: thepub\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "thepriv")
        self.assertEqual(pub, "thepub")

    def test_password_priority_over_public(self):
        """Если есть и Password и Public — приоритет у Password (новый формат)."""
        from vless_installer.modules.xray_install import _parse_x25519_keys
        output = (
            "Private key: PRIV\n"
            "Public key: OLDPUB\n"
            "Password: NEWPUB\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "PRIV")
        self.assertEqual(pub, "NEWPUB")

    def test_partial_match_fallback(self):
        """Если стандартных ключей нет, но есть 'private'/'public' в названии поля."""
        from vless_installer.modules.xray_install import _parse_x25519_keys
        output = (
            "my private special: PRIV123\n"
            "the public one: PUB456\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "PRIV123")
        self.assertEqual(pub, "PUB456")

    def test_strips_whitespace(self):
        """Пробелы вокруг значений обрезаются."""
        from vless_installer.modules.xray_install import _parse_x25519_keys
        output = "Private key:   spaced_priv   \nPublic key:   spaced_pub   \n"
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "spaced_priv")
        self.assertEqual(pub, "spaced_pub")


# ══════════════════════════════════════════════════════════════════════════════
#  _parse_x25519_field — regex-поиск поля
# ══════════════════════════════════════════════════════════════════════════════
class TestParseX25519Field(unittest.TestCase):
    """_parse_x25519_field: возвращает последний токен первой матч-строки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_last_token_of_first_match(self):
        from vless_installer.modules.xray_install import _parse_x25519_field
        output = "Private key: ABC123\nPublic key: DEF456\n"
        # pattern "private" — matches first line
        result = _parse_x25519_field("private", output)
        self.assertEqual(result, "ABC123")

    def test_case_insensitive(self):
        from vless_installer.modules.xray_install import _parse_x25519_field
        output = "PRIVATE KEY: ABC123\n"
        result = _parse_x25519_field("private", output)
        self.assertEqual(result, "ABC123")

    def test_returns_empty_when_no_match(self):
        from vless_installer.modules.xray_install import _parse_x25519_field
        result = _parse_x25519_field("nonexistent", "Private key: ABC")
        self.assertEqual(result, "")

    def test_returns_empty_for_empty_output(self):
        from vless_installer.modules.xray_install import _parse_x25519_field
        self.assertEqual(_parse_x25519_field("anything", ""), "")

    def test_takes_first_matching_line(self):
        """Если несколько строк матчат — берётся первая."""
        from vless_installer.modules.xray_install import _parse_x25519_field
        output = "Public key: FIRST\nPublic key: SECOND\n"
        result = _parse_x25519_field("public", output)
        self.assertEqual(result, "FIRST")

    def test_regex_pattern(self):
        """Pattern — это regex, можно использовать более сложные выражения."""
        from vless_installer.modules.xray_install import _parse_x25519_field
        output = "Private key: secret123\n"
        result = _parse_x25519_field(r"private\s+key", output)
        self.assertEqual(result, "secret123")


# ══════════════════════════════════════════════════════════════════════════════
#  _xray_version_norm — нормализация версии
# ══════════════════════════════════════════════════════════════════════════════
class TestXrayVersionNorm(unittest.TestCase):
    """_xray_version_norm: формат 15 символов (5 цифр на octet × 3)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_strips_v_prefix(self):
        from vless_installer.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("v25.4.30"),
                         "000250000400030")

    def test_without_v_prefix(self):
        from vless_installer.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("25.4.30"),
                         "000250000400030")

    def test_two_octets_pads_zero(self):
        """Двухоктетная версия добивается третьим нулём."""
        from vless_installer.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("1.2"),
                         "000010000200000")

    def test_one_octet(self):
        from vless_installer.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("5"),
                         "000050000000000")

    def test_four_octets_truncated(self):
        """Четырёхоктетная версия обрезается до трёх."""
        from vless_installer.modules.xray_install import _xray_version_norm
        result = _xray_version_norm("1.2.3.4")
        self.assertEqual(result, "000010000200003")

    def test_non_numeric_returns_zeros(self):
        """Не-числовые octets → 15 нулей."""
        from vless_installer.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("abc.def.ghi"),
                         "000000000000000")

    def test_empty_string_returns_zeros(self):
        from vless_installer.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm(""), "000000000000000")

    def test_lexicographic_comparison(self):
        """Нормализованные строки можно сравнивать лексикографически."""
        from vless_installer.modules.xray_install import _xray_version_norm
        v1 = _xray_version_norm("v25.4.30")
        v2 = _xray_version_norm("v1.2.3")
        # 25.x > 1.x — нормализованная v1 должна быть меньше v25
        self.assertLess(v2, v1)
        v3 = _xray_version_norm("v25.5.1")
        v4 = _xray_version_norm("v25.4.99")
        # 25.5.1 > 25.4.99
        self.assertGreater(v3, v4)

    def test_zero_padding_for_single_digit(self):
        """Одноразрядные octets добиваются до 5 знаков."""
        from vless_installer.modules.xray_install import _xray_version_norm
        result = _xray_version_norm("1.2.3")
        self.assertEqual(len(result), 15)
        self.assertEqual(result, "000010000200003")


# ══════════════════════════════════════════════════════════════════════════════
#  _xray_find_config — поиск config.json
# ══════════════════════════════════════════════════════════════════════════════
class TestXrayFindConfig(unittest.TestCase):
    """_xray_find_config: возвращает первый существующий путь к config.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_etc_xray_first_when_exists(self):
        from vless_installer.modules.xray_install import _xray_find_config
        etc_xray = Path(self._tmpdir) / "etc_xray"
        etc_xray.mkdir()
        etc_cfg = etc_xray / "config.json"
        etc_cfg.write_text("{}")
        with patch("vless_installer.modules.xray_install.Path") as mock_path:
            # Path("/etc/xray/config.json") → etc_cfg
            # Path("/usr/local/etc/xray/config.json") → not exists
            def _path_constructor(p):
                if "/etc/xray/config.json" in str(p):
                    return etc_cfg
                return Path("/usr/local/etc/xray/config.json")
            mock_path.side_effect = _path_constructor
            # Path.exists для /etc/xray/config.json — True
            with patch.object(Path, "exists",
                              lambda self: str(self) == str(etc_cfg)):
                result = _xray_find_config()
        self.assertEqual(result, etc_cfg)

    def test_returns_none_when_no_config_found(self):
        from vless_installer.modules.xray_install import _xray_find_config
        with patch.object(Path, "exists", return_value=False):
            result = _xray_find_config()
        self.assertIsNone(result)


# ══════════════════════════════════════════════════════════════════════════════
#  _xray_current_version — парсинг версии из `xray version`
# ══════════════════════════════════════════════════════════════════════════════
class TestXrayCurrentVersion(unittest.TestCase):
    """_xray_current_version: regex-парсинг версии из stdout."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_parses_semantic_version(self):
        from vless_installer.modules import xray_install
        stdout = "Xray 1.8.6 (XTLS, WeChat) 2024-01-15\n"
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=stdout,
                                                 stderr="")), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v1.8.6")

    def test_parses_date_based_version(self):
        from vless_installer.modules import xray_install
        stdout = "Xray 25.4.30 (XTLS, WeChat) 2025-04-30\n"
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=stdout,
                                                 stderr="")), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v25.4.30")

    def test_returns_v0_0_0_when_no_match(self):
        from vless_installer.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout="some garbage",
                                                 stderr="")), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v0.0.0")

    def test_returns_v0_0_0_on_exception(self):
        from vless_installer.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          side_effect=Exception("xray not found")), \
             patch("shutil.which", return_value=None):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v0.0.0")


# ══════════════════════════════════════════════════════════════════════════════
#  _xray_get_release_info — парсинг GitHub API
# ══════════════════════════════════════════════════════════════════════════════
class TestXrayGetReleaseInfo(unittest.TestCase):
    """_xray_get_release_info: stable vs prerelease, 3 попытки."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_stable_release(self):
        from vless_installer.modules import xray_install
        api_response = json.dumps({
            "tag_name": "v25.4.30",
            "prerelease": False,
        })
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=api_response,
                                                 stderr="")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info(prerelease=False)
        self.assertIsNotNone(result)
        self.assertEqual(result["tag_name"], "v25.4.30")

    def test_prerelease_takes_first_from_list(self):
        from vless_installer.modules import xray_install
        api_response = json.dumps([
            {"tag_name": "v25.5.0-rc1", "prerelease": True},
            {"tag_name": "v25.4.30", "prerelease": False},
        ])
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=api_response,
                                                 stderr="")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info(prerelease=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["tag_name"], "v25.5.0-rc1")

    def test_returns_none_on_empty_stdout(self):
        from vless_installer.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=1,
                                                 stdout="",
                                                 stderr="network error")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info()
        self.assertIsNone(result)

    def test_returns_none_on_invalid_json(self):
        from vless_installer.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout="{invalid json",
                                                 stderr="")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info()
        self.assertIsNone(result)

    def test_stable_returns_none_when_no_tag_name(self):
        """Stable-режим требует tag_name в ответе — иначе None."""
        from vless_installer.modules import xray_install
        api_response = json.dumps({"message": "Not Found"})
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=api_response,
                                                 stderr="")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info(prerelease=False)
        self.assertIsNone(result)


# ══════════════════════════════════════════════════════════════════════════════
#  _detect_xhttp_mode_support — date-based vs semantic version
# ══════════════════════════════════════════════════════════════════════════════
class TestDetectXhttpModeSupport(unittest.TestCase):
    """_detect_xhttp_mode_support: XHTTP 'mode' field не поддерживается
    в date-based версиях (major >= 25)."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._fake_core.XHTTP_MODE_SUPPORTED = True  # дефолт перед вызовом
        self._fake_core.XRAY_BIN = "/usr/local/bin/xray"
        self._fake_core._run = MagicMock()
        self._fake_core.warn = MagicMock()
        self._fake_core.info = MagicMock()

    def test_date_based_version_disables_mode(self):
        """Xray 25.x.x — date-based, mode не поддерживается → False."""
        from vless_installer.modules import xray_install
        self._fake_core._run.return_value = MagicMock(
            returncode=0, stdout="Xray 25.4.30 (XTLS) 2025-04-30\n", stderr="")
        xray_install._detect_xhttp_mode_support()
        self.assertFalse(self._fake_core.XHTTP_MODE_SUPPORTED)

    def test_semantic_version_enables_mode(self):
        """Xray 1.x.x или 2.x.x — semantic, mode поддерживается → True."""
        from vless_installer.modules import xray_install
        self._fake_core._run.return_value = MagicMock(
            returncode=0, stdout="Xray 1.8.6 (XTLS) 2024-01-15\n", stderr="")
        xray_install._detect_xhttp_mode_support()
        self.assertTrue(self._fake_core.XHTTP_MODE_SUPPORTED)

    def test_unparseable_version_disables_mode(self):
        """Если версию не удалось распарсить → False (безопасный дефолт)."""
        from vless_installer.modules import xray_install
        self._fake_core._run.return_value = MagicMock(
            returncode=0, stdout="garbage without version", stderr="")
        xray_install._detect_xhttp_mode_support()
        self.assertFalse(self._fake_core.XHTTP_MODE_SUPPORTED)


# ══════════════════════════════════════════════════════════════════════════════
#  _verify_sha256 — верификация SHA256
# ══════════════════════════════════════════════════════════════════════════════
class TestVerifySha256(unittest.TestCase):
    """_verify_sha256: hash match / mismatch / skip when no checksums."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._fake_core.command_exists = MagicMock(return_value=True)
        self._fake_core.warn = MagicMock()
        self._fake_core.success = MagicMock()
        self._fake_core.RED = ""
        self._fake_core.NC = ""
        self._fake_core._run = MagicMock()
        self._tmpdir = tempfile.mkdtemp()
        self._file_path = Path(self._tmpdir) / "xray.zip"
        self._file_path.write_bytes(b"fake binary content")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_hash_matches_returns_true(self):
        from vless_installer.modules import xray_install
        expected_hash = "a" * 64
        actual_hash = "a" * 64
        checksums_content = f"{expected_hash} *xray.zip\n"
        # _run вызывается дважды: curl (download checksums), sha256sum
        self._fake_core._run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # curl
            MagicMock(returncode=0, stdout=f"{actual_hash}  {self._file_path}",
                      stderr=""),  # sha256sum
        ]
        with patch("tempfile.NamedTemporaryFile") as mock_tmp:
            tmp_file = MagicMock()
            tmp_file.name = str(Path(self._tmpdir) / "checksums.txt")
            tmp_file.__enter__ = lambda self: tmp_file
            tmp_file.__exit__ = lambda *a: None
            mock_tmp.return_value = tmp_file
            with patch.object(Path, "read_text", return_value=checksums_content), \
                 patch.object(Path, "stat") as mock_stat, \
                 patch.object(Path, "unlink"):
                mock_stat.return_value = MagicMock(st_size=len(checksums_content))
                result = xray_install._verify_sha256(
                    self._file_path,
                    "https://example.com/checksums.txt",
                    "xray.zip",
                )
        self.assertTrue(result)

    def test_returns_true_when_sha256sum_missing(self):
        """Если sha256sum не установлен — верификация пропускается (True)."""
        from vless_installer.modules import xray_install
        self._fake_core.command_exists.return_value = False
        result = xray_install._verify_sha256(
            self._file_path, "https://x", "xray.zip")
        self.assertTrue(result)
        self._fake_core.warn.assert_called()
        self._fake_core._run.assert_not_called()

    def test_returns_true_when_checksums_download_fails(self):
        """Если checksums.txt не удалось скачать — верификация пропускается."""
        from vless_installer.modules import xray_install
        # curl вернул returncode != 0
        self._fake_core._run.return_value = MagicMock(returncode=1,
                                                       stdout="", stderr="err")
        tmp_path = Path(self._tmpdir) / "checksums.txt"
        with patch("tempfile.NamedTemporaryFile") as mock_tmp:
            tmp_file = MagicMock()
            tmp_file.name = str(tmp_path)
            tmp_file.__enter__ = lambda self: tmp_file
            tmp_file.__exit__ = lambda *a: None
            mock_tmp.return_value = tmp_file
            with patch.object(Path, "stat") as mock_stat, \
                 patch.object(Path, "unlink"):
                mock_stat.return_value = MagicMock(st_size=0)
                result = xray_install._verify_sha256(
                    self._file_path,
                    "https://example.com/checksums.txt",
                    "xray.zip",
                )
        self.assertTrue(result)


# ══════════════════════════════════════════════════════════════════════════════
#  create_xray_service — генерация systemd-unit (3 ветки)
# ══════════════════════════════════════════════════════════════════════════════
class TestCreateXrayService(unittest.TestCase):
    """create_xray_service: генерация systemd-unit для 3 режимов
    (xhttp / AWG / classic REALITY)."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._service_file = Path(self._tmpdir) / "xray.service"

        c = self._fake_core
        c.info = MagicMock()
        c.success = MagicMock()
        c._run = MagicMock(return_value=MagicMock(returncode=0,
                                                   stdout="", stderr=""))
        c.PARAM_SOCKET_PATH = "/var/run/xray/vless-reality.sock"
        c.PARAM_USE_DNSCRYPT = False
        c.PROTOCOL_MODE = "reality"
        c.AWG_EXIT_ENABLED = False
        c.XRAY_SERVICE = self._service_file
        c.XRAY_BIN = "/usr/local/bin/xray"
        c.CONFIG_DIR = Path("/etc/xray")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _read_service(self) -> str:
        return self._service_file.read_text()

    def test_xhttp_mode_no_exec_start_pre(self):
        """xhttp: нет ExecStartPre (Nginx терминирует TLS, сокет не нужен)."""
        from vless_installer.modules import xray_install
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("xHTTP", content)
        self.assertNotIn("ExecStartPre", content)
        self.assertIn("ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json",
                      content)

    def test_awg_mode_no_exec_start_pre(self):
        """AWG: нет ExecStartPre (Xray слушает TCP напрямую, без Unix-сокета)."""
        from vless_installer.modules import xray_install
        self._fake_core.AWG_EXIT_ENABLED = True
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("AWG", content)
        self.assertNotIn("ExecStartPre", content)

    def test_classic_reality_has_exec_start_pre_mkdir(self):
        """Classic REALITY: ExecStartPre создаёт директорию для сокета."""
        from vless_installer.modules import xray_install
        # PARAM_SOCKET_PATH родительская директория должна создаваться
        with patch.object(Path, "mkdir"), \
             patch.object(Path, "chmod"):
            xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("REALITY", content)
        self.assertIn("ExecStartPre=/bin/mkdir -p /var/run/xray", content)

    def test_dnscrypt_adds_after_dependency(self):
        """PARAM_USE_DNSCRYPT=True → After= добавляет dnscrypt-proxy.service."""
        from vless_installer.modules import xray_install
        self._fake_core.PARAM_USE_DNSCRYPT = True
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("dnscrypt-proxy.service", content)
        self.assertIn("Wants=network-online.target dnscrypt-proxy.service", content)

    def test_service_has_hardening_options(self):
        """Проверка базовых hardening-опций: User, NoNewPrivileges, LimitNOFILE."""
        from vless_installer.modules import xray_install
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("User=xray", content)
        self.assertIn("Group=xray", content)
        self.assertIn("NoNewPrivileges=true", content)
        self.assertIn("LimitNOFILE=1048576", content)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
                      content)

    def test_service_has_exec_reload_restart(self):
        """ExecReload через явный restart (Xray 26.x не обрабатывает SIGHUP)."""
        from vless_installer.modules import xray_install
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("ExecReload=/bin/systemctl restart xray", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
