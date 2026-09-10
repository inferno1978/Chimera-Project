#!/usr/bin/env python3
"""
tests/test_xray_install.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/xray_install.py — установка/обновление
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
 10. _install_autoupdate_service — bash-скрипт автообновления: сравнение
     версий «старше» (апгрейд только «вверх»), поведенческие прогоны в
     песочнице с фейковыми xray/curl/systemctl.
"""
from __future__ import annotations

import json
import shutil
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


# ══════════════════════════════════════════════════════════════════════════════
#  _parse_x25519_keys — парсинг вывода `xray x25519`
# ══════════════════════════════════════════════════════════════════════════════
class TestParseX25519Keys(unittest.TestCase):
    """_parse_x25519_keys: корректный парсинг для всех версий Xray."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_old_format_private_public(self):
        """Старый формат Xray <v26: 'Private key: xxx\\nPublic key: yyy'."""
        from chimera.modules.xray_install import _parse_x25519_keys
        output = (
            "Private key: abc123DEF456\n"
            "Public key:  XYZ789ghi012\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "abc123DEF456")
        self.assertEqual(pub, "XYZ789ghi012")

    def test_new_format_v26_password(self):
        """Новый формат Xray v26+: 'Password: xxx' (это public key)."""
        from chimera.modules.xray_install import _parse_x25519_keys
        output = (
            "Password: v2.6-public-key-here\n"
            "Private key: v2.6-private-key-here\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "v2.6-private-key-here")
        self.assertEqual(pub, "v2.6-public-key-here")

    def test_returns_empty_for_empty_output(self):
        from chimera.modules.xray_install import _parse_x25519_keys
        priv, pub = _parse_x25519_keys("")
        self.assertEqual(priv, "")
        self.assertEqual(pub, "")

    def test_returns_empty_for_garbage(self):
        from chimera.modules.xray_install import _parse_x25519_keys
        priv, pub = _parse_x25519_keys("hello\nworld\nfoo bar baz")
        self.assertEqual(priv, "")
        self.assertEqual(pub, "")

    def test_skips_lines_without_colon(self):
        """Строки без ':' пропускаются."""
        from chimera.modules.xray_install import _parse_x25519_keys
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
        from chimera.modules.xray_install import _parse_x25519_keys
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
        from chimera.modules.xray_install import _parse_x25519_keys
        output = (
            "my private special: PRIV123\n"
            "the public one: PUB456\n"
        )
        priv, pub = _parse_x25519_keys(output)
        self.assertEqual(priv, "PRIV123")
        self.assertEqual(pub, "PUB456")

    def test_strips_whitespace(self):
        """Пробелы вокруг значений обрезаются."""
        from chimera.modules.xray_install import _parse_x25519_keys
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
        from chimera.modules.xray_install import _parse_x25519_field
        output = "Private key: ABC123\nPublic key: DEF456\n"
        # pattern "private" — matches first line
        result = _parse_x25519_field("private", output)
        self.assertEqual(result, "ABC123")

    def test_case_insensitive(self):
        from chimera.modules.xray_install import _parse_x25519_field
        output = "PRIVATE KEY: ABC123\n"
        result = _parse_x25519_field("private", output)
        self.assertEqual(result, "ABC123")

    def test_returns_empty_when_no_match(self):
        from chimera.modules.xray_install import _parse_x25519_field
        result = _parse_x25519_field("nonexistent", "Private key: ABC")
        self.assertEqual(result, "")

    def test_returns_empty_for_empty_output(self):
        from chimera.modules.xray_install import _parse_x25519_field
        self.assertEqual(_parse_x25519_field("anything", ""), "")

    def test_takes_first_matching_line(self):
        """Если несколько строк матчат — берётся первая."""
        from chimera.modules.xray_install import _parse_x25519_field
        output = "Public key: FIRST\nPublic key: SECOND\n"
        result = _parse_x25519_field("public", output)
        self.assertEqual(result, "FIRST")

    def test_regex_pattern(self):
        """Pattern — это regex, можно использовать более сложные выражения."""
        from chimera.modules.xray_install import _parse_x25519_field
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
        from chimera.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("v25.4.30"),
                         "000250000400030")

    def test_without_v_prefix(self):
        from chimera.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("25.4.30"),
                         "000250000400030")

    def test_two_octets_pads_zero(self):
        """Двухоктетная версия добивается третьим нулём."""
        from chimera.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("1.2"),
                         "000010000200000")

    def test_one_octet(self):
        from chimera.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("5"),
                         "000050000000000")

    def test_four_octets_truncated(self):
        """Четырёхоктетная версия обрезается до трёх."""
        from chimera.modules.xray_install import _xray_version_norm
        result = _xray_version_norm("1.2.3.4")
        self.assertEqual(result, "000010000200003")

    def test_non_numeric_returns_zeros(self):
        """Не-числовые octets → 15 нулей."""
        from chimera.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm("abc.def.ghi"),
                         "000000000000000")

    def test_empty_string_returns_zeros(self):
        from chimera.modules.xray_install import _xray_version_norm
        self.assertEqual(_xray_version_norm(""), "000000000000000")

    def test_lexicographic_comparison(self):
        """Нормализованные строки можно сравнивать лексикографически."""
        from chimera.modules.xray_install import _xray_version_norm
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
        from chimera.modules.xray_install import _xray_version_norm
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
        from chimera.modules.xray_install import _xray_find_config
        etc_xray = Path(self._tmpdir) / "etc_xray"
        etc_xray.mkdir()
        etc_cfg = etc_xray / "config.json"
        etc_cfg.write_text("{}")
        with patch("chimera.modules.xray_install.Path") as mock_path:
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
        from chimera.modules.xray_install import _xray_find_config
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
        from chimera.modules import xray_install
        stdout = "Xray 1.8.6 (XTLS, WeChat) 2024-01-15\n"
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=stdout,
                                                 stderr="")), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v1.8.6")

    def test_parses_date_based_version(self):
        from chimera.modules import xray_install
        stdout = "Xray 25.4.30 (XTLS, WeChat) 2025-04-30\n"
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=stdout,
                                                 stderr="")), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v25.4.30")

    def test_returns_v0_0_0_when_no_match(self):
        from chimera.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout="some garbage",
                                                 stderr="")), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_current_version()
        self.assertEqual(result, "v0.0.0")

    def test_returns_v0_0_0_on_exception(self):
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=1,
                                                 stdout="",
                                                 stderr="network error")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info()
        self.assertIsNone(result)

    def test_returns_none_on_invalid_json(self):
        from chimera.modules import xray_install
        with patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout="{invalid json",
                                                 stderr="")), \
             patch("time.sleep"):
            result = xray_install._xray_get_release_info()
        self.assertIsNone(result)

    def test_stable_returns_none_when_no_tag_name(self):
        """Stable-режим требует tag_name в ответе — иначе None."""
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
        self._fake_core._run.return_value = MagicMock(
            returncode=0, stdout="Xray 25.4.30 (XTLS) 2025-04-30\n", stderr="")
        xray_install._detect_xhttp_mode_support()
        self.assertFalse(self._fake_core.XHTTP_MODE_SUPPORTED)

    def test_semantic_version_enables_mode(self):
        """Xray 1.x.x или 2.x.x — semantic, mode поддерживается → True."""
        from chimera.modules import xray_install
        self._fake_core._run.return_value = MagicMock(
            returncode=0, stdout="Xray 1.8.6 (XTLS) 2024-01-15\n", stderr="")
        xray_install._detect_xhttp_mode_support()
        self.assertTrue(self._fake_core.XHTTP_MODE_SUPPORTED)

    def test_unparseable_version_disables_mode(self):
        """Если версию не удалось распарсить → False (безопасный дефолт)."""
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
        self._fake_core.command_exists.return_value = False
        result = xray_install._verify_sha256(
            self._file_path, "https://x", "xray.zip")
        self.assertTrue(result)
        self._fake_core.warn.assert_called()
        self._fake_core._run.assert_not_called()

    def test_returns_true_when_checksums_download_fails(self):
        """Если checksums.txt не удалось скачать — верификация пропускается."""
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("xHTTP", content)
        self.assertNotIn("ExecStartPre", content)
        self.assertIn("ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json",
                      content)

    def test_awg_mode_no_exec_start_pre(self):
        """AWG: нет ExecStartPre (Xray слушает TCP напрямую, без Unix-сокета)."""
        from chimera.modules import xray_install
        self._fake_core.AWG_EXIT_ENABLED = True
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("AWG", content)
        self.assertNotIn("ExecStartPre", content)

    def test_classic_reality_has_exec_start_pre_mkdir(self):
        """Classic REALITY: ExecStartPre создаёт директорию для сокета."""
        from chimera.modules import xray_install
        # PARAM_SOCKET_PATH родительская директория должна создаваться
        with patch.object(Path, "mkdir"), \
             patch.object(Path, "chmod"):
            xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("REALITY", content)
        self.assertIn("ExecStartPre=/bin/mkdir -p /var/run/xray", content)

    def test_dnscrypt_adds_after_dependency(self):
        """PARAM_USE_DNSCRYPT=True → After= добавляет dnscrypt-proxy.service."""
        from chimera.modules import xray_install
        self._fake_core.PARAM_USE_DNSCRYPT = True
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("dnscrypt-proxy.service", content)
        self.assertIn("Wants=network-online.target dnscrypt-proxy.service", content)

    def test_service_has_hardening_options(self):
        """Проверка базовых hardening-опций: User, NoNewPrivileges, LimitNOFILE."""
        from chimera.modules import xray_install
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
        from chimera.modules import xray_install
        self._fake_core.PROTOCOL_MODE = "xhttp"
        xray_install.create_xray_service()
        content = self._read_service()
        self.assertIn("ExecReload=/bin/systemctl restart xray", content)


# ══════════════════════════════════════════════════════════════════════════════
#  Wave 4 миграция: install_xray / _xray_do_upgrade / _xray_update_geo_runetfreedom
#  → fetch_package(XRAY_INSTALLER_SPEC) / fetch_package(XRAY_ZIP_SPEC) /
#    fetch_package(GEOSITE_SPEC) / fetch_package(GEOIP_SPEC)
# ══════════════════════════════════════════════════════════════════════════════
class TestInstallXrayMigration(unittest.TestCase):
    """install_xray после Wave 4 миграции: использует fetch_package() вместо
    inline curl-циклов.

    4 сценария:
      1. success  — Метод 1 (XRAY_INSTALLER_SPEC) сразу успешен.
      2. fallback — Метод 1 fails, Метод 2 (XRAY_ZIP_SPEC) успешен.
      3. manual   — Все сети упали, manual hint + retry → success.
      4. fail     — Все методы упали → die().
    """

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        c = self._fake_core
        # Базовые атрибуты
        c.info = MagicMock()
        c.warn = MagicMock()
        c.success = MagicMock()
        c.die = MagicMock(side_effect=SystemExit(1))
        c._run = MagicMock()
        c.command_exists = MagicMock(return_value=True)
        c.XRAY_BIN = Path("/usr/local/bin/xray")
        c.STAGE_XRAY_DONE = False
        c.CONFIG_DIR = Path("/etc/xray")
        c.XRAY_BACKUP_DIR = Path("/var/backups/xray")
        c.PROGRESS = MagicMock()
        c.XHTTP_MODE_SUPPORTED = False
        # Цвета — пустые строки (для print())
        for attr in ("YELLOW", "NC", "BOLD", "WHITE", "CYAN", "GREEN", "DIM",
                     "RED", "BLUE"):
            setattr(c, attr, "")
        # Patch shutil.which и Path.mkdir/chmod
        self._shutil_which_patcher = patch("shutil.which",
                                           return_value="/usr/local/bin/xray")
        self._shutil_which_patcher.start()
        self._path_mkdir_patcher = patch.object(Path, "mkdir",
                                                lambda self, *a, **kw: None)
        self._path_mkdir_patcher.start()
        self._path_chmod_patcher = patch.object(Path, "chmod",
                                                lambda self, *a, **kw: None)
        self._path_chmod_patcher.start()
        self._os_chown_patcher = patch("os.chown", lambda *a, **kw: None)
        self._os_chown_patcher.start()
        # _detect_xhttp_mode_support мокаем чтобы не запускать xray
        self._xhttp_patcher = patch(
            "chimera.modules.xray_install._detect_xhttp_mode_support",
            return_value=None,
        )
        self._xhttp_patcher.start()

    def tearDown(self):
        self._shutil_which_patcher.stop()
        self._path_mkdir_patcher.stop()
        self._path_chmod_patcher.stop()
        self._os_chown_patcher.stop()
        self._xhttp_patcher.stop()

    def _mock_run_responses(self, arch="x86_64", xray_version="Xray 25.4.30\n"):
        """Настраивает _run mock для возврата разных ответов на разные команды."""
        def _run_side_effect(cmd, *a, **kw):
            # cmd может быть list
            if isinstance(cmd, (list, tuple)):
                cmd_list = list(cmd)
            else:
                cmd_list = [str(cmd)]
            cmd_str = " ".join(str(x) for x in cmd_list)
            if "uname" in cmd_str:
                return MagicMock(returncode=0, stdout=arch, stderr="")
            if "id" in cmd_str and "xray" in cmd_str:
                # xray user exists → returncode 0
                return MagicMock(returncode=0, stdout="", stderr="")
            if "useradd" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "chown" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "curl" in cmd_str and "api.github.com" in cmd_str:
                # GitHub API response
                if "releases/latest" in cmd_str:
                    return MagicMock(returncode=0,
                                     stdout=json.dumps({"tag_name": "v25.4.30"}),
                                     stderr="")
                if "releases?per_page" in cmd_str or "per_page" in cmd_str:
                    return MagicMock(returncode=0,
                                     stdout=json.dumps([
                                         {"tag_name": "v25.4.30", "prerelease": False}
                                     ]),
                                     stderr="")
                return MagicMock(returncode=0, stdout="{}", stderr="")
            if "version" in cmd_str:
                return MagicMock(returncode=0, stdout=xray_version, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        self._fake_core._run.side_effect = _run_side_effect

    def _patch_xray_bin_exists(self, exists=True):
        """Патчит Path.exists так что /usr/local/bin/xray 'существует' или нет."""
        original_exists = Path.exists
        def mock_exists(self, *a, **kw):
            s = str(self)
            if s == "/usr/local/bin/xray":
                return exists
            return original_exists(self, *a, **kw)
        return patch.object(Path, "exists", mock_exists)

    def test_method1_installer_spec_success(self):
        """Сценарий 1 (success): Метод 1 — fetch_package(XRAY_INSTALLER_SPEC) → True.
        install_xray успешно завершается, XRAY_BIN установлен, STAGE_XRAY_DONE=True.
        """
        from chimera.modules import xray_install
        self._mock_run_responses()

        with patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("os.access", return_value=True):
            xray_install.install_xray()

        # fetch_package был вызван минимум 1 раз (Метод 1)
        self.assertTrue(mock_fetch.called)
        # Первый вызов — с XRAY_INSTALLER_SPEC (name="Xray-installer")
        first_call = mock_fetch.call_args_list[0]
        spec_arg = first_call[0][0] if first_call[0] else first_call[1].get('spec')
        self.assertIsNotNone(spec_arg)
        self.assertEqual(spec_arg.name, "Xray-installer")
        # XRAY_BIN установлен
        self.assertEqual(self._fake_core.XRAY_BIN, Path("/usr/local/bin/xray"))
        # STAGE_XRAY_DONE = True
        self.assertTrue(self._fake_core.STAGE_XRAY_DONE)

    def test_method2_zip_spec_fallback(self):
        """Сценарий 2 (fallback): Метод 1 fails, Метод 2 — fetch_package(XRAY_ZIP_SPEC, tag=, arch=) → True.
        Проверяем что fetch_package вызывается с XRAY_ZIP_SPEC и kwargs tag/arch.
        """
        from chimera.modules import xray_install
        self._mock_run_responses()

        call_count = [0]
        def _fetch_side_effect(spec, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                # Метод 1 — XRAY_INSTALLER_SPEC — fail
                return False
            # Метод 2 — XRAY_ZIP_SPEC — success
            return True

        with patch("chimera.modules.download_manager.fetch_package",
                   side_effect=_fetch_side_effect) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("os.access", return_value=True):
            xray_install.install_xray()

        # fetch_package вызван минимум 2 раза (Метод 1 + Метод 2)
        self.assertGreaterEqual(mock_fetch.call_count, 2)
        # Первый вызов — XRAY_INSTALLER_SPEC
        first_spec = mock_fetch.call_args_list[0][0][0]
        self.assertEqual(first_spec.name, "Xray-installer")
        # Второй вызов — XRAY_ZIP_SPEC с tag= и arch=
        second_call = mock_fetch.call_args_list[1]
        second_spec = second_call[0][0]
        self.assertEqual(second_spec.name, "Xray-core")
        self.assertIn("tag", second_call[1],
                      "Метод 2 должен передавать tag= kwarg в fetch_package")
        self.assertIn("arch", second_call[1],
                      "Метод 2 должен передавать arch= kwarg в fetch_package")
        # XRAY_BIN установлен
        self.assertEqual(self._fake_core.XRAY_BIN, Path("/usr/local/bin/xray"))
        self.assertTrue(self._fake_core.STAGE_XRAY_DONE)

    def test_manual_hint_retry_success(self):
        """Сценарий 3 (manual): все сети падают, manual hint + retry → success.

        Метод 1 fails, Метод 2 fails, manual hint показывается, retry через
        fetch_package → True → xray_installed.
        """
        from chimera.modules import xray_install
        self._mock_run_responses()

        call_count = [0]
        def _fetch_side_effect(spec, **kw):
            call_count[0] += 1
            # Первые 2 вызова (Метод 1 + Метод 2) — fail
            if call_count[0] <= 2:
                return False
            # Retry в manual loop — success
            return True

        with patch("chimera.modules.download_manager.fetch_package",
                   side_effect=_fetch_side_effect) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("os.access", return_value=True), \
             patch("builtins.input", return_value=""), \
             patch("chimera.modules.xray_install._xray_try_local_zip",
                   return_value=False) as mock_local:
            xray_install.install_xray()

        # fetch_package вызван минимум 3 раза (Метод 1 + Метод 2 + retry)
        self.assertGreaterEqual(mock_fetch.call_count, 3)
        # _xray_try_local_zip вызван (manual retry проверяет локальные файлы)
        self.assertTrue(mock_local.called)
        # XRAY_BIN установлен
        self.assertEqual(self._fake_core.XRAY_BIN, Path("/usr/local/bin/xray"))
        self.assertTrue(self._fake_core.STAGE_XRAY_DONE)

    def test_all_methods_fail(self):
        """Сценарий 4 (fail): все методы упали → die().

        Метод 1 fails, Метод 2 fails, manual retry fails, input() raises
        EOFError → die("Установка прервана пользователем.") → SystemExit.
        """
        from chimera.modules import xray_install
        self._mock_run_responses()

        def _input_side_effect(*a, **kw):
            raise EOFError("simulated user interrupt")

        with patch("chimera.modules.download_manager.fetch_package",
                   return_value=False) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("os.access", return_value=True), \
             patch("builtins.input", side_effect=_input_side_effect), \
             patch("chimera.modules.xray_install._xray_try_local_zip",
                   return_value=False):
            # die() должна вызвать SystemExit (через side_effect в setUp)
            with self.assertRaises(SystemExit):
                xray_install.install_xray()
            # die была вызвана
            self._fake_core.die.assert_called()
        # fetch_package вызван минимум 2 раза (Метод 1 + Метод 2)
        self.assertGreaterEqual(mock_fetch.call_count, 2)


# ══════════════════════════════════════════════════════════════════════════════
#  _xray_do_upgrade — Wave 4 миграция: fetch_package(XRAY_ZIP_SPEC, tag, arch)
# ══════════════════════════════════════════════════════════════════════════════
class TestXrayDoUpgradeMigration(unittest.TestCase):
    """_xray_do_upgrade после Wave 4: использует fetch_package(XRAY_ZIP_SPEC)
    вместо одного прямого URL (без зеркал)."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        c = self._fake_core
        c.info = MagicMock()
        c.warn = MagicMock()
        c.success = MagicMock()
        c._run = MagicMock()
        c.XRAY_BIN = Path("/usr/local/bin/xray")
        for attr in ("YELLOW", "NC", "BOLD", "WHITE", "CYAN", "GREEN", "DIM",
                     "RED", "BLUE"):
            setattr(c, attr, "")
        self._shutil_which_patcher = patch("shutil.which",
                                           return_value="/usr/local/bin/xray")
        self._shutil_which_patcher.start()
        self._path_mkdir_patcher = patch.object(Path, "mkdir",
                                                lambda self, *a, **kw: None)
        self._path_mkdir_patcher.start()
        self._path_chmod_patcher = patch.object(Path, "chmod",
                                                lambda self, *a, **kw: None)
        self._path_chmod_patcher.start()

    def tearDown(self):
        self._shutil_which_patcher.stop()
        self._path_mkdir_patcher.stop()
        self._path_chmod_patcher.stop()

    def test_uses_fetch_package_with_zip_spec(self):
        """_xray_do_upgrade вызывает fetch_package(XRAY_ZIP_SPEC, tag=, arch=)."""
        from chimera.modules import xray_install

        # _run mock: uname -m → x86_64, xray version → v25.4.30
        def _run_side_effect(cmd, *a, **kw):
            cmd_list = list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)]
            cmd_str = " ".join(str(x) for x in cmd_list)
            if "uname" in cmd_str:
                return MagicMock(returncode=0, stdout="x86_64", stderr="")
            if "version" in cmd_str:
                return MagicMock(returncode=0, stdout="Xray 25.4.30\n", stderr="")
            if "test" in cmd_str:
                # xray run -test
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        self._fake_core._run.side_effect = _run_side_effect

        # _xray_geo_is_runetfreedom → True (skip geo update)
        # _xray_current_version → "v25.4.30"
        with patch("chimera.modules.xray_install._xray_geo_is_runetfreedom",
                   return_value=True), \
             patch("chimera.modules.xray_install._xray_current_version",
                   return_value="v25.4.30"), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("shutil.copy2", return_value=None), \
             patch("shutil.which", return_value="/usr/local/bin/xray"):
            result = xray_install._xray_do_upgrade(tag="v25.4.30")

        # fetch_package вызван
        self.assertTrue(mock_fetch.called)
        # С XRAY_ZIP_SPEC
        call_args = mock_fetch.call_args
        spec_arg = call_args[0][0]
        self.assertEqual(spec_arg.name, "Xray-core")
        # С tag= и arch= kwargs
        self.assertEqual(call_args[1].get("tag"), "v25.4.30")
        self.assertIn("arch", call_args[1])
        # Результат True
        self.assertTrue(result)

    def test_returns_false_when_fetch_package_fails(self):
        """fetch_package возвращает False → _xray_do_upgrade возвращает False."""
        from chimera.modules import xray_install

        def _run_side_effect(cmd, *a, **kw):
            cmd_list = list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)]
            cmd_str = " ".join(str(x) for x in cmd_list)
            if "uname" in cmd_str:
                return MagicMock(returncode=0, stdout="x86_64", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        self._fake_core._run.side_effect = _run_side_effect

        with patch("chimera.modules.xray_install._xray_geo_is_runetfreedom",
                   return_value=True), \
             patch("chimera.modules.xray_install._xray_current_version",
                   return_value="v25.4.30"), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=False) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("shutil.copy2", return_value=None):
            result = xray_install._xray_do_upgrade(tag="v25.4.30")

        self.assertFalse(result)
        self.assertTrue(mock_fetch.called)

    def test_returns_false_on_unsupported_arch(self):
        """Неподдерживаемая архитектура → False (без fetch_package)."""
        from chimera.modules import xray_install

        def _run_side_effect(cmd, *a, **kw):
            cmd_list = list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)]
            cmd_str = " ".join(str(x) for x in cmd_list)
            if "uname" in cmd_str:
                return MagicMock(returncode=0, stdout="mips64", stderr="")  # unsupported
            return MagicMock(returncode=0, stdout="", stderr="")
        self._fake_core._run.side_effect = _run_side_effect

        # _xray_do_upgrade использует subprocess.check_output(["uname", "-m"])
        # напрямую (не через _run) — патчим subprocess.check_output.
        with patch("chimera.modules.xray_install.subprocess.check_output",
                   return_value=b"mips64"), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as mock_fetch:
            result = xray_install._xray_do_upgrade(tag="v25.4.30")

        self.assertFalse(result)
        # fetch_package НЕ вызван (abort до скачивания)
        self.assertFalse(mock_fetch.called)


# ══════════════════════════════════════════════════════════════════════════════
#  _xray_update_geo_runetfreedom — Wave 4 миграция: fetch_package(GEOSITE_SPEC/GEOIP_SPEC)
# ══════════════════════════════════════════════════════════════════════════════
class TestXrayUpdateGeoRunetfreedomMigration(unittest.TestCase):
    """_xray_update_geo_runetfreedom после Wave 4: использует fetch_package
    (GEOSITE_SPEC, GEOIP_SPEC) вместо inline curl+wget цикла."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        c = self._fake_core
        c.info = MagicMock()
        c.warn = MagicMock()
        c.success = MagicMock()
        c._run = MagicMock()
        for attr in ("YELLOW", "NC", "BOLD", "WHITE", "CYAN", "GREEN", "DIM",
                     "RED", "BLUE"):
            setattr(c, attr, "")
        self._shutil_which_patcher = patch("shutil.which",
                                           return_value="/usr/local/bin/xray")
        self._shutil_which_patcher.start()
        self._path_mkdir_patcher = patch.object(Path, "mkdir",
                                                lambda self, *a, **kw: None)
        self._path_mkdir_patcher.start()

    def tearDown(self):
        self._shutil_which_patcher.stop()
        self._path_mkdir_patcher.stop()

    def test_calls_fetch_package_for_both_geo_specs(self):
        """Вызывает fetch_package(GEOSITE_SPEC) и fetch_package(GEOIP_SPEC)."""
        from chimera.modules import xray_install

        with patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as mock_fetch, \
             patch("pathlib.Path.exists", return_value=False), \
             patch("builtins.input", return_value="n"):
            result = xray_install._xray_update_geo_runetfreedom()

        # fetch_package вызван дважды (geosite + geoip)
        self.assertEqual(mock_fetch.call_count, 2)
        # Первый вызов — GEOSITE_SPEC (name="geosite.dat")
        first_spec = mock_fetch.call_args_list[0][0][0]
        self.assertEqual(first_spec.name, "geosite.dat")
        # Второй вызов — GEOIP_SPEC (name="geoip.dat")
        second_spec = mock_fetch.call_args_list[1][0][0]
        self.assertEqual(second_spec.name, "geoip.dat")
        # Результат True (geosite.dat скачан)
        self.assertTrue(result)

    def test_returns_true_when_only_geosite_succeeds(self):
        """Если только geosite.dat скачан → True (geoip может провалиться)."""
        from chimera.modules import xray_install

        def _fetch_side_effect(spec, **kw):
            if spec.name == "geosite.dat":
                return True
            return False  # geoip fails

        with patch("chimera.modules.download_manager.fetch_package",
                   side_effect=_fetch_side_effect), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("builtins.input", return_value="n"):
            result = xray_install._xray_update_geo_runetfreedom()

        self.assertTrue(result)

    def test_returns_false_when_both_fail(self):
        """Если оба geo-файла провалились → False (после manual retry тоже fail)."""
        from chimera.modules import xray_install

        with patch("chimera.modules.download_manager.fetch_package",
                   return_value=False), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("builtins.input", return_value="n"):
            result = xray_install._xray_update_geo_runetfreedom()

        self.assertFalse(result)


class TestXrayGeoIsRunetfreedomCaseInsensitive(unittest.TestCase):
    """ REGRESSION: _xray_geo_is_runetfreedom должен использовать
    case-insensitive grep (-i флаг).

    Теги в geosite.dat хранятся в ВЕРХНЕМ регистре (RU-AVAILABLE-ONLY-INSIDE),
    а функция ищет строчное 'ru-available-only-inside'. Без -i grep не находил
    тег → функция возвращала False даже для валидного runetfreedom geosite.dat →
    при каждом запуске установщика гео-файлы перескачивались (~73 МБ).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uses_case_insensitive_grep_flag(self):
        """grep должен вызываться с -i флагом (в составе объединённой строки -qaFi)."""
        from chimera.modules import xray_install
        import subprocess as _sp
        # Мокаем Path.exists чтобы кандидат-путь "существовал".
        with patch("pathlib.Path.exists", return_value=True), \
             patch("subprocess.run",
                   return_value=_sp.CompletedProcess(
                       args=[], returncode=0, stdout="", stderr="")) as mock_run:
            xray_install._xray_geo_is_runetfreedom()
            # subprocess.run вызывается как subprocess.run(["grep", "-qaFi", ...])
            # Ищем grep-вызовы и проверяем что в строке флагов есть 'i'.
            grep_calls = [c for c in mock_run.call_args_list
                          if c[0] and c[0][0] and isinstance(c[0][0], list)
                          and c[0][0][:1] == ["grep"]]
            self.assertTrue(grep_calls, "Должен быть хотя бы один grep вызов")
            for c in grep_calls:
                cmd_args = c[0][0]
                # cmd_args = ["grep", "-qaFi", "ru-available-only-inside", "/path"]
                self.assertGreaterEqual(len(cmd_args), 2,
                                        f"grep команда должна иметь флаги: {cmd_args}")
                flags = cmd_args[1]
                self.assertIn("i", flags,
                              f"grep flags '{flags}' должны содержать 'i' (case-insensitive). "
                              f"Полная команда: {cmd_args}")

    def test_finds_uppercase_tag_in_real_geosite(self):
        """Если geosite.dat содержит RU-AVAILABLE-ONLY-INSIDE (uppercase),
        функция должна вернуть True через case-insensitive grep."""
        from chimera.modules import xray_install
        import subprocess as _sp
        # Имитируем: grep с -i находит (rc=0), без -i не находит (rc=1).
        def fake_grep(cmd, **kw):
            if isinstance(cmd, list) and len(cmd) > 1 and "i" in cmd[1]:
                return _sp.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return _sp.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

        with patch("pathlib.Path.exists", return_value=True), \
             patch("subprocess.run", side_effect=fake_grep):
            result = xray_install._xray_geo_is_runetfreedom()
        self.assertTrue(result,
                        "Должна вернуть True для geosite.dat с uppercase тегом")


# ══════════════════════════════════════════════════════════════════════════════
#  generate_xray_config_xhttp — генерация config.json для XHTTP TLS.
#  Регрессионный тест на багу «_xhttp_s3 not associated with a value»
#  при активном профиле CDN masking.
# ══════════════════════════════════════════════════════════════════════════════
class TestGenerateXhttpConfigCdnMasking(unittest.TestCase):
    """generate_xray_config_xhttp: корректная работа при XHTTP_CDN_MASKING=True.

    Регрессионный тест: при активном CDN masking profile переменная
    _xhttp_s3 должна определяться в if-ветке (а не _xhttp_s3_dict),
    иначе 'xhttpSettings': _xhttp_s3 падает с UnboundLocalError.

    Баг проявлялся только в runtime (при установке), т.к. в тестах
    generate_xray_config_xhttp не вызывалась — она пишет config.json
    и запускает xray -test.
    """

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        c = self._fake_core
        # Минимальные атрибуты для generate_xray_config_xhttp.
        c.PROTOCOL_MODE = "xhttp"
        c.XHTTP_MODE = "stream-up"
        c.XHTTP_PATH = "/test-cdn.ts"
        c.PARAM_DOMAIN = "test.example.com"
        c.PARAM_UUID = "test-uuid-1234"
        c.XHTTP_BACKEND_PORT = 8443  # будет переопределён на 7443
        c.IS_IPV6_AVAILABLE = False
        c.PARAM_DOMAIN_STRATEGY = "UseIPv4"
        c.DNSCRYPT_LISTEN_PORT = 5353
        c.DNSCRYPT_INSTALLED = False
        c.DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
        c.AWG_FWMARK = 0
        c.AWG_EXIT_ENABLED = False
        c.SPLIT_TUNNEL_ENABLED = False
        c.SERVER_PORT = 443
        c.XRAY_BIN = "/usr/local/bin/xray"
        c.INSTALL_COMPLETED = False
        c.command_exists = lambda x: True
        # Мокаем _run чтобы xray -test возвращал успех.
        c._run = MagicMock(return_value=MagicMock(returncode=0, stdout="active",
                                                   stderr=""))
        c._set_config_owner = MagicMock()
        c._apply_stats_to_config = lambda cfg: None
        c._xray_log_block = lambda: {"loglevel": "warning"}
        c.XHTTP_MODE_SUPPORTED = True
        # Colors
        for attr in ("YELLOW", "NC", "BOLD", "WHITE", "CYAN", "GREEN",
                     "DIM", "RED", "BLUE"):
            setattr(c, attr, "")
        # Реальный temp-каталог для CONFIG_DIR (write_text нужен)
        self._tmp = tempfile.mkdtemp()
        c.CONFIG_DIR = Path(self._tmp)
        # Patch Path.mkdir/chmod (как в других тестах).
        self._path_mkdir_patcher = patch.object(Path, "mkdir",
                                                lambda self, *a, **kw: None)
        self._path_mkdir_patcher.start()
        self._path_chmod_patcher = patch.object(Path, "chmod",
                                                lambda self, *a, **kw: None)
        self._path_chmod_patcher.start()
        self._os_chown_patcher = patch("os.chown", lambda *a, **kw: None)
        self._os_chown_patcher.start()
        self._os_geteuid_patcher = patch("os.geteuid", return_value=0)
        self._os_geteuid_patcher.start()

    def tearDown(self):
        self._path_mkdir_patcher.stop()
        self._path_chmod_patcher.stop()
        self._os_chown_patcher.stop()
        self._os_geteuid_patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_cdn_masking_active_no_unbound_local_error(self):
        """XHTTP_CDN_MASKING=True: generate_xray_config_xhttp не падает.

        Регрессия: раньше в if-ветке переменная называлась _xhttp_s3_dict,
        а в streamSettings ссылалась на _xhttp_s3 → UnboundLocalError.
        """
        self._fake_core.XHTTP_CDN_MASKING = True
        from chimera.modules import xray_install
        # Не должно бросить UnboundLocalError.
        xray_install.generate_xray_config_xhttp()
        # config.json должен быть создан.
        cfg_file = Path(self._tmp) / "config.json"
        self.assertTrue(cfg_file.exists(),
            "config.json must be created")
        cfg = json.loads(cfg_file.read_text())
        # Проверка: используется CDN-masking профиль (port 7443).
        self.assertEqual(cfg["inbounds"][0]["port"], 7443,
            f"Port must be 7443 (CDN_MASKING_INBOUND_PORT), "
            f"got {cfg['inbounds'][0]['port']}")
        # Проверка: xhttpSettings.extra присутствует (CDN-masking профиль).
        xhttp_settings = cfg["inbounds"][0]["streamSettings"]["xhttpSettings"]
        self.assertIn("extra", xhttp_settings,
            "xhttpSettings.extra must be present for CDN masking profile")
        self.assertGreater(len(xhttp_settings["extra"]), 20,
            f"CDN masking extra should have 24+ fields, "
            f"got {len(xhttp_settings['extra'])}")
        # Проверка: __backend_port НЕ должен попасть в финальный конфиг
        # (он извлекается через .pop()).
        self.assertNotIn("__backend_port", xhttp_settings,
            "__backend_port must be popped from xhttpSettings before "
            "writing to config.json")
        # Проверка: XHTTP_BACKEND_PORT в core обновлён до 7443.
        self.assertEqual(self._fake_core.XHTTP_BACKEND_PORT, 7443,
            f"core.XHTTP_BACKEND_PORT must be updated to 7443, "
            f"got {self._fake_core.XHTTP_BACKEND_PORT}")

    def test_cdn_masking_inactive_uses_simple_xhttp(self):
        """XHTTP_CDN_MASKING=False: используется простой _build_xhttp_settings.

        Регрессия: при CDN masking выключеном, должен работать старый
        путь через _build_xhttp_settings() — port остаётся 8443,
        extra — базовый (xPaddingBytes, noGRPCHeader, noSSEHeader, ...).
        """
        self._fake_core.XHTTP_CDN_MASKING = False
        from chimera.modules import xray_install
        xray_install.generate_xray_config_xhttp()
        cfg_file = Path(self._tmp) / "config.json"
        self.assertTrue(cfg_file.exists())
        cfg = json.loads(cfg_file.read_text())
        # При CDN masking выключенном — стандартный port 8443.
        self.assertEqual(cfg["inbounds"][0]["port"], 8443,
            f"Port must be 8443 (standard XHTTP_BACKEND_PORT) when "
            f"CDN masking off, got {cfg['inbounds'][0]['port']}")
        # xhttpSettings присутствует, но без расширенных CDN-masking полей.
        xhttp_settings = cfg["inbounds"][0]["streamSettings"]["xhttpSettings"]
        self.assertIn("extra", xhttp_settings)
        # В простом режиме extra содержит xPaddingBytes (базовый padding).
        self.assertIn("xPaddingBytes", xhttp_settings["extra"])
        # Но не содержит sessionKey (это CDN-masking специфичное поле).
        self.assertNotIn("sessionKey", xhttp_settings["extra"],
            "sessionKey must NOT be present in simple XHTTP mode "
            "(only in CDN masking profile)")


# ══════════════════════════════════════════════════════════════════════════════
#  _install_autoupdate_service — bash-скрипт автообновления
#  (сравнение «старше»: апгрейд только «вверх», авто-даунгрейд исключён)
# ══════════════════════════════════════════════════════════════════════════════
class TestAutoupdateScript(unittest.TestCase):
    """Поведенческие тесты bash-скрипта xray-autoupdate.sh.

    Скрипт извлекается РЕАЛЬНЫМ вызовом _install_autoupdate_service()
    (Path.write_text перехватывается — на диск ничего не пишется),
    константы LOG/BACKUP_DIR заворачиваются в tmp-песочницу, а
    xray/curl/systemctl заменяются фейками в PATH — реальная система
    не затрагивается. Проверяются три исхода:
      • установленная НОВЕЕ stable-latest → ничего не делать
        (регрессия: прежнее сравнение «на равенство» даунгрейдило
        флот 26.9.9 до stable v26.3.27 ближайшей ночью);
      • равна → ничего не делать;
      • СТАРШЕ → обновление (curl идёт за release-zip).
    """

    def _capture_script(self) -> str:
        """Генерирует скрипт через настоящий _install_autoupdate_service().

        Path.write_text перехватывается (ничего не пишется на диск),
        _core подменяется exec-фейком, _run — no-op (реальный exec-ядро
        звонил бы в systemctl).
        """
        import io
        from contextlib import redirect_stdout

        core = _setup_core_in_sysmodules()
        # no-op _run: systemctl-вызовы из python-части не выполняются
        core._run = lambda cmd, **kw: MagicMock(
            returncode=0, stdout="", stderr="")
        captured = {}

        def _fake_write_text(self, data, *a, **kw):
            captured[str(self)] = data
            return len(data or "")

        with patch.object(Path, "write_text", _fake_write_text), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None), \
             patch.object(Path, "chmod", lambda self, *a, **kw: None), \
             patch("sys.argv", ["installer.py"]):
            from chimera.modules import xray_install
            buf = io.StringIO()
            with redirect_stdout(buf):
                xray_install._install_autoupdate_service()

        script = captured.get("/usr/local/bin/xray-autoupdate.sh")
        self.assertIsNotNone(
            script, "xray-autoupdate.sh не сгенерирован (или путь изменён)")
        return script

    def _run_script(self, script: str, installed: str, latest: str):
        """Запускает скрипт в песочнице с фейковыми xray/curl/systemctl.

        Возвращает (returncode, текст лога, строки-вызовы curl).
        curl: releases/latest → JSON {"tag_name": latest}; любой другой
        URL → фиксируется и rc=1 (сети нет — путь загрузки обрывается
        сразу после записи URL, что и проверяем).
        """
        import os
        import subprocess as sp

        sbx = Path(tempfile.mkdtemp(prefix="xau_test_"))
        try:
            bin_dir = sbx / "bin"
            bin_dir.mkdir()
            log_path = sbx / "autoupdate.log"
            backups = sbx / "backups"
            curl_calls = sbx / "curl_calls.txt"
            systemctl_calls = sbx / "systemctl_calls.txt"

            (bin_dir / "xray").write_text(
                "#!/bin/sh\n"
                f"echo 'Xray {installed} (fake for autoupdate test)'\n")
            (bin_dir / "xray").chmod(0o755)

            (bin_dir / "curl").write_text(textwrap.dedent(f"""\
                #!/bin/sh
                echo "$*" >> "{curl_calls}"
                case "$*" in
                  *releases/latest*)
                    echo '{{"tag_name": "{latest}"}}'
                    exit 0
                    ;;
                esac
                exit 1
            """))
            (bin_dir / "curl").chmod(0o755)

            (bin_dir / "systemctl").write_text(
                "#!/bin/sh\n"
                f'echo "systemctl $*" >> "{systemctl_calls}"\n'
                "exit 0\n")
            (bin_dir / "systemctl").chmod(0o755)

            # Две абсолютные константы скрипта → песочница
            sandboxed = script.replace(
                'LOG="/var/log/xray-autoupdate.log"', f'LOG="{log_path}"'
            ).replace(
                'BACKUP_DIR="/var/backups/xray/binaries"',
                f'BACKUP_DIR="{backups}"'
            )
            self.assertNotIn("/var/log/xray-autoupdate.log", sandboxed)
            script_path = sbx / "xray-autoupdate.sh"
            script_path.write_text(sandboxed)
            script_path.chmod(0o755)

            env = dict(os.environ)
            env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
            proc = sp.run(["bash", str(script_path)], env=env,
                          capture_output=True, text=True, timeout=60)

            log_text = log_path.read_text() if log_path.exists() else ""
            curl_lines = ([l for l in curl_calls.read_text().splitlines()
                           if l.strip()] if curl_calls.exists() else [])
            systemctl_used = (systemctl_calls.exists() and
                              systemctl_calls.read_text().strip() != "")
            return proc.returncode, log_text, curl_lines, systemctl_used
        finally:
            shutil.rmtree(sbx, ignore_errors=True)

    # ── исходники: сравнение «старше», а не «равно» ────────────────────

    def test_script_uses_older_not_equal_comparison(self):
        script = self._capture_script()
        # новая схема: нормализованные значения сравниваются «старше»
        self.assertIn("CUR_N", script)
        self.assertIn('> "$LAT_N"', script)
        # прежняя схема «только на равенство» исчезла
        self.assertNotIn('== "$(_norm "$LATEST")"', script)

    # ── установленная НОВЕЕ stable → ничего не делать ──────────────────

    def test_installed_newer_than_stable_skips(self):
        """Регрессия: флот 26.9.9 при stable v26.3.27 не даунгрейдится."""
        script = self._capture_script()
        rc, log, curls, systemctl_used = self._run_script(
            script, installed="26.9.9", latest="v26.3.27")
        self.assertEqual(rc, 0)
        self.assertIn("новее stable-latest", log)
        downloads = [c for c in curls if "releases/download" in c]
        self.assertEqual(downloads, [], "даунгрейд не должен качать release-zip")
        self.assertFalse(systemctl_used, "сервис не должен перезапускаться")

    def test_gate_era_downgrade_not_touched(self):
        """5c-даунгрейд 26.7.28: ядро новее stable — автапдейт молчит."""
        script = self._capture_script()
        rc, log, curls, systemctl_used = self._run_script(
            script, installed="26.7.28", latest="v26.3.27")
        self.assertEqual(rc, 0)
        downloads = [c for c in curls if "releases/download" in c]
        self.assertEqual(downloads, [])
        self.assertFalse(systemctl_used)

    def test_pregate_26627_not_touched(self):
        """5c-даунгрейд 26.6.27 (до-гейт): новее stable — автапдейт молчит."""
        script = self._capture_script()
        rc, log, curls, systemctl_used = self._run_script(
            script, installed="26.6.27", latest="v26.3.27")
        self.assertEqual(rc, 0)
        downloads = [c for c in curls if "releases/download" in c]
        self.assertEqual(downloads, [])
        self.assertFalse(systemctl_used)

    # ── равна stable → ничего не делать ─────────────────────────────────

    def test_installed_equal_skips(self):
        script = self._capture_script()
        rc, log, curls, _ = self._run_script(
            script, installed="26.3.27", latest="v26.3.27")
        self.assertEqual(rc, 0)
        self.assertIn("актуальна", log)
        downloads = [c for c in curls if "releases/download" in c]
        self.assertEqual(downloads, [])

    # ── установленная СТАРШЕ stable → обновление ───────────────────────

    def test_installed_older_triggers_update(self):
        script = self._capture_script()
        rc, log, curls, _ = self._run_script(
            script, installed="1.2.3", latest="v26.3.27")
        # фейковый curl валит загрузку — скрипт честно отчитывается rc=1
        # (systemd-unit: SuccessExitStatus=0 1)
        self.assertEqual(rc, 1)
        self.assertIn("Обновление v1.2.3 → v26.3.27", log)
        self.assertIn("ERROR: Ошибка загрузки", log)
        downloads = [c for c in curls if "releases/download" in c]
        self.assertTrue(
            any("releases/download/v26.3.27/Xray-linux-64.zip" in c
                for c in downloads),
            f"ожидалась загрузка release-zip v26.3.27, curl-вызовы: {curls}")

    def test_multidigit_versions_compare_numerically(self):
        """26.10.1 новее 26.9.9: нормализация %05d не путает разряды."""
        script = self._capture_script()
        rc, log, curls, _ = self._run_script(
            script, installed="26.9.9", latest="v26.10.1")
        self.assertEqual(rc, 1)
        self.assertIn("Обновление v26.9.9 → v26.10.1", log)
        self.assertTrue(
            any("releases/download/v26.10.1/" in c for c in curls),
            "ожидалась загрузка v26.10.1 (числовое сравнение разрядов)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
