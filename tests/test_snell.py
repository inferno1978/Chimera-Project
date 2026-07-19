#!/usr/bin/env python3
"""
tests/test_snell.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/snell.py — основного модуля Snell v4.

Покрывает:
  1. Генерацию клиентской ссылки (_build_snell_link)
  2. URL-encoding PSK (base64 символы +/= должны быть закодированы)
  3. Поддержку всех obfs режимов (tls/http/off)
  4. Валидацию имён пользователей (_validate_username)
  5. Генерацию PSK (_generate_psk — 32 байта, base64)
  6. Выделение портов из диапазона 30000-30999
  7. Генерацию INI-конфига (_write_user_config)
  8. Генерацию sing-box outbound JSON
  9. Генерацию Clash Meta proxy-узла
  10. Public API: get_user_link, get_user_clash_proxy, get_user_singbox_outbound,
      is_any_active (no-op когда Snell не установлен)
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
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


class TestBuildSnellLink(unittest.TestCase):
    """_build_snell_link — генерация клиентской ссылки snell://."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_basic_link_format(self):
        """Базовый формат: snell://<psk>@<server>:<port>?obfs=<obfs>&...#<tag>"""
        from chimera.modules.snell import _build_snell_link
        link = _build_snell_link(
            server="1.2.3.4", port=30001, psk="testpsk1234",
            obfs="tls", obfs_host="vpn.example.com",
            tag="snell-test",
        )
        self.assertTrue(link.startswith("snell://"))
        self.assertIn("1.2.3.4:30001", link)
        self.assertIn("obfs=tls", link)
        self.assertIn("obfs-host=vpn.example.com", link)
        self.assertTrue(link.endswith("#snell-test"))

    def test_psk_url_encoded(self):
        """PSK с base64-символами +/= должен быть URL-закодирован."""
        from chimera.modules.snell import _build_snell_link
        # base64 от 32 байт часто содержит +, /, = — проверяем кодирование.
        psk = "dGVzdHBzaw==+/"  # содержит +, /, =
        link = _build_snell_link(
            server="1.2.3.4", port=30001, psk=psk,
            obfs="off", obfs_host="", tag="t",
        )
        # PSK в URL должен быть закодирован: + → %2B, / → %2F, = → %3D
        self.assertIn("%2B", link)
        self.assertIn("%2F", link)
        self.assertIn("%3D", link)
        # Сам psk в чистом виде НЕ должен встречаться (только закодированный).
        self.assertNotIn("+" + psk[0], link.replace("%2B", ""))

    def test_obfs_off_omits_obfs_host(self):
        """obfs=off → параметр obfs-host не должен быть в URL."""
        from chimera.modules.snell import _build_snell_link
        link = _build_snell_link(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="off", obfs_host="should-not-appear",
            tag="t",
        )
        self.assertIn("obfs=off", link)
        self.assertNotIn("obfs-host", link)

    def test_obfs_http_includes_host(self):
        """obfs=http → параметр obfs-host должен быть."""
        from chimera.modules.snell import _build_snell_link
        link = _build_snell_link(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="http", obfs_host="example.com",
            tag="t",
        )
        self.assertIn("obfs=http", link)
        self.assertIn("obfs-host=example.com", link)

    def test_tag_url_encoded(self):
        """Тег (после #) должен быть URL-закодирован."""
        from chimera.modules.snell import _build_snell_link
        link = _build_snell_link(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="tls", obfs_host="h",
            tag="test tag with spaces",
        )
        # Пробелы в tag должны быть закодированы как %20.
        self.assertIn("%20", link)
        self.assertNotIn(" test ", link)

    def test_empty_tag_omits_hash(self):
        """Пустой tag → # не должен быть в URL."""
        from chimera.modules.snell import _build_snell_link
        link = _build_snell_link(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="off", obfs_host="", tag="",
        )
        self.assertNotIn("#", link)


class TestUsernameValidation(unittest.TestCase):
    """_validate_username — проверка формата имени пользователя."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_names(self):
        from chimera.modules.snell import _validate_username
        for name in ("alice", "bob", "user1", "user_name", "user-name",
                     "abc", "AliceInChains", "ABCDEFGH"):  # 8 символов — валидно
            with self.subTest(name=name):
                self.assertTrue(_validate_username(name),
                                f"Имя {name!r} должно быть валидным")

    def test_rejects_too_short(self):
        from chimera.modules.snell import _validate_username
        for name in ("a", "ab", ""):
            with self.subTest(name=name):
                self.assertFalse(_validate_username(name),
                                 f"Имя {name!r} слишком короткое (< 3 симв)")

    def test_rejects_too_long(self):
        from chimera.modules.snell import _validate_username
        # 17 символов — больше лимита (16).
        long_name = "a" * 17
        self.assertFalse(_validate_username(long_name))

    def test_rejects_digit_first(self):
        """Имя должно начинаться с буквы, не с цифры."""
        from chimera.modules.snell import _validate_username
        for name in ("1abc", "2user", "9snell"):
            with self.subTest(name=name):
                self.assertFalse(_validate_username(name))

    def test_rejects_special_chars(self):
        """Имя не должно содержать спецсимволы (кроме _ и -)."""
        from chimera.modules.snell import _validate_username
        for name in ("alice@bob", "user.name", "alice/bob", "alice#bob",
                     "alice bob", "alice!bob"):
            with self.subTest(name=name):
                self.assertFalse(_validate_username(name))

    def test_rejects_uppercase_only_first(self):
        """Имя может начинаться с заглавной буквы — это валидно."""
        from chimera.modules.snell import _validate_username
        # Это должно проходить — формат [a-zA-Z] позволяет заглавные.
        self.assertTrue(_validate_username("Alice"))


class TestPskGeneration(unittest.TestCase):
    """_generate_psk — генерация Pre-Shared Key."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_base64_string(self):
        from chimera.modules.snell import _generate_psk, PSK_BYTES
        psk = _generate_psk()
        # Декодируем base64 — должно быть PSK_BYTES байт.
        decoded = base64.b64decode(psk)
        self.assertEqual(len(decoded), PSK_BYTES)

    def test_returns_different_values_each_call(self):
        from chimera.modules.snell import _generate_psk
        psk1 = _generate_psk()
        psk2 = _generate_psk()
        self.assertNotEqual(psk1, psk2,
                            "PSK должен быть разным при каждом вызове")

    def test_psk_is_valid_base64(self):
        from chimera.modules.snell import _generate_psk
        psk = _generate_psk()
        # Должно декодироваться без ошибок.
        decoded = base64.b64decode(psk)
        self.assertEqual(len(decoded), 32)


class TestPortAllocation(unittest.TestCase):
    """_allocate_port — выделение портов из диапазона 30000-30999."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_first_port_is_30000(self):
        """Первый выданный порт должен быть 30000 (начало диапазона)."""
        from chimera.modules.snell import _allocate_port
        port = _allocate_port({"users": []})
        self.assertEqual(port, 30000)

    def test_skips_occupied_ports(self):
        """Если порт занят — выделяется следующий свободный."""
        from chimera.modules.snell import _allocate_port
        state = {
            "users": [
                {"username": "u1", "port": 30000},
                {"username": "u2", "port": 30001},
                {"username": "u3", "port": 30002},
            ]
        }
        port = _allocate_port(state)
        self.assertEqual(port, 30003)

    def test_handles_gaps_in_port_range(self):
        """Если порт в середине диапазона свободен — он выделяется."""
        from chimera.modules.snell import _allocate_port
        state = {
            "users": [
                {"username": "u1", "port": 30000},
                {"username": "u2", "port": 30002},  # 30001 пропущен
            ]
        }
        port = _allocate_port(state)
        self.assertEqual(port, 30001)

    def test_raises_when_range_exhausted(self):
        """Когда все 1000 портов заняты — RuntimeError."""
        from chimera.modules.snell import (
            _allocate_port, PORT_RANGE_START, PORT_RANGE_END,
        )
        # Создаём state со всеми портами занятыми.
        all_ports = list(range(PORT_RANGE_START, PORT_RANGE_END + 1))
        state = {"users": [{"username": f"u{i}", "port": p}
                            for i, p in enumerate(all_ports)]}
        with self.assertRaises(RuntimeError):
            _allocate_port(state)


class TestWriteUserConfig(unittest.TestCase):
    """_write_user_config — генерация INI-конфига /etc/snell/<user>.conf."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_writes_ini_format(self):
        """Конфиг должен быть в INI-формате с секцией [snell-server]."""
        from chimera.modules.snell import _write_user_config
        with patch("chimera.modules.snell.CONFIG_DIR", self._tmpdir):
            cfg_path = _write_user_config(
                username="alice", port=30001, psk="testpsk",
                obfs="tls", obfs_host="vpn.example.com",
            )
        content = cfg_path.read_text()
        self.assertIn("[snell-server]", content)
        self.assertIn("listen = 0.0.0.0:30001", content)
        self.assertIn("psk = testpsk", content)
        self.assertIn("ipv6 = false", content)
        self.assertIn("obfs = tls", content)
        self.assertIn("obfs-host = vpn.example.com", content)

    def test_obfs_off_omits_host(self):
        """obfs=off → obfs-host не должен быть в конфиге."""
        from chimera.modules.snell import _write_user_config
        with patch("chimera.modules.snell.CONFIG_DIR", self._tmpdir):
            cfg_path = _write_user_config(
                username="alice", port=30001, psk="psk",
                obfs="off", obfs_host="",
            )
        content = cfg_path.read_text()
        self.assertIn("obfs = off", content)
        self.assertNotIn("obfs-host", content)

    def test_chmod_640(self):
        """Конфиг должен иметь chmod 0o640 (group-readable, не world)."""
        from chimera.modules.snell import _write_user_config
        with patch("chimera.modules.snell.CONFIG_DIR", self._tmpdir):
            cfg_path = _write_user_config(
                username="alice", port=30001, psk="psk",
                obfs="tls", obfs_host="h",
            )
        self.assertEqual(oct(cfg_path.stat().st_mode & 0o777), '0o640')


class TestSingboxOutbound(unittest.TestCase):
    """_gen_singbox_outbound — генерация JSON для sing-box."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_basic_structure(self):
        from chimera.modules.snell import _gen_singbox_outbound
        ob = _gen_singbox_outbound(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="tls", obfs_host="vpn.example.com",
        )
        self.assertEqual(ob["type"], "snell")
        self.assertEqual(ob["tag"], "snell-out")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 30001)
        self.assertEqual(ob["password"], "psk")
        self.assertEqual(ob["obfs"]["type"], "tls")
        self.assertEqual(ob["obfs"]["host"], "vpn.example.com")

    def test_obfs_off_omits_obfs_section(self):
        from chimera.modules.snell import _gen_singbox_outbound
        ob = _gen_singbox_outbound(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="off", obfs_host="",
        )
        self.assertNotIn("obfs", ob)


class TestClashProxy(unittest.TestCase):
    """_gen_clash_proxy — генерация Clash Meta proxy-узла."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_basic_structure(self):
        from chimera.modules.snell import _gen_clash_proxy
        px = _gen_clash_proxy(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="tls", obfs_host="vpn.example.com",
            name="Snell-test",
        )
        self.assertEqual(px["name"], "Snell-test")
        self.assertEqual(px["type"], "snell")
        self.assertEqual(px["server"], "1.2.3.4")
        self.assertEqual(px["port"], 30001)
        self.assertEqual(px["psk"], "psk")
        self.assertEqual(px["obfs-opts"]["mode"], "tls")
        self.assertEqual(px["obfs-opts"]["host"], "vpn.example.com")

    def test_obfs_off(self):
        from chimera.modules.snell import _gen_clash_proxy
        px = _gen_clash_proxy(
            server="1.2.3.4", port=30001, psk="psk",
            obfs="off", obfs_host="",
            name="Snell",
        )
        self.assertEqual(px["obfs-opts"]["mode"], "off")
        self.assertNotIn("host", px["obfs-opts"])


class TestPublicApiNoInstall(unittest.TestCase):
    """Public API должен возвращать None/False когда Snell не установлен.

    Это критичный контракт — rest_api.py и subscription.py полагаются
    на то, что функции не падают при отсутствии Snell.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_is_any_active_false_when_not_installed(self):
        from chimera.modules.snell import is_any_active
        # В тестовой среде нет бинарника/сервисов — должно быть False.
        self.assertFalse(is_any_active())

    def test_get_user_link_returns_none_when_not_installed(self):
        from chimera.modules.snell import get_user_link
        self.assertIsNone(get_user_link("alice"))

    def test_get_user_clash_proxy_returns_none_when_not_installed(self):
        from chimera.modules.snell import get_user_clash_proxy
        self.assertIsNone(get_user_clash_proxy("alice"))

    def test_get_user_singbox_outbound_returns_none_when_not_installed(self):
        from chimera.modules.snell import get_user_singbox_outbound
        self.assertIsNone(get_user_singbox_outbound("alice"))

    def test_is_installed_false_in_test_env(self):
        from chimera.modules.snell import _is_installed
        self.assertFalse(_is_installed())


class TestRestApiIntegration(unittest.TestCase):
    """Интеграционный тест: _generate_vless_links с Snell не падает."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_generate_vless_links_does_not_crash_without_snell(self):
        """_generate_vless_links должен работать без установленного Snell."""
        from chimera.modules import rest_api
        fake_state = {
            "domain": "test.example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "test_pub",
            "short_id": "abcd",
            "uuid": "test-uuid",
        }
        fake_user = {"uuid": "u1", "name": "alice", "email": "alice@x.com"}
        with patch.object(rest_api, "_get_state", return_value=fake_state):
            links = rest_api._generate_vless_links(fake_user)
        # Должна быть хотя бы VLESS-ссылка, Snell-ссылки не должно быть.
        self.assertGreater(len(links), 0)
        self.assertEqual(links[0]["protocol"], "reality")
        snell_links = [l for l in links if l["protocol"] == "snell"]
        self.assertEqual(len(snell_links), 0,
                         "Snell-ссылка не должна появляться без установленного Snell")

    def test_generate_clash_config_does_not_crash_without_snell(self):
        """_generate_clash_config должен работать без Snell."""
        from chimera.modules import rest_api
        fake_state = {
            "domain": "test.example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "test_pub",
            "short_id": "abcd",
            "fingerprint": "chrome",
            "xtls_flow": "xtls-rprx-vision",
        }
        fake_user = {"uuid": "u1", "name": "alice"}
        with patch.object(rest_api, "_get_state", return_value=fake_state):
            clash = rest_api._generate_clash_config(fake_user)
        self.assertIn("VLESS-Reality", clash)
        # Snell не должен быть в конфиге если не установлен.
        self.assertNotIn("type: snell", clash)

    def test_generate_singbox_config_does_not_crash_without_snell(self):
        """_generate_singbox_config должен работать без Snell."""
        from chimera.modules import rest_api
        fake_state = {
            "domain": "test.example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "test_pub",
            "short_id": "abcd",
            "fingerprint": "chrome",
            "xtls_flow": "xtls-rprx-vision",
        }
        fake_user = {"uuid": "u1", "name": "alice"}
        with patch.object(rest_api, "_get_state", return_value=fake_state):
            sb_str = rest_api._generate_singbox_config(fake_user)
        sb = json.loads(sb_str)
        # Должен быть VLESS outbound, Snell outbound-ов быть не должно.
        self.assertGreater(len(sb["outbounds"]), 0)
        self.assertEqual(sb["outbounds"][0]["type"], "vless")
        snell_obs = [o for o in sb["outbounds"] if o.get("type") == "snell"]
        self.assertEqual(len(snell_obs), 0)

    def test_singbox_config_no_compat_note_when_snell_inactive(self):
        """Когда Snell не активен — ключ _snell_compat_note должен ОТСУТСТВОВАТЬ
        в JSON (не пустая строка, а именно отсутствие ключа)."""
        from chimera.modules import rest_api
        fake_state = {
            "domain": "test.example.com", "server_port": 443,
            "protocol_mode": "reality", "public_key": "p", "short_id": "s",
            "fingerprint": "chrome", "xtls_flow": "xtls-rprx-vision",
        }
        fake_user = {"uuid": "u1", "name": "alice"}
        with patch.object(rest_api, "_get_state", return_value=fake_state):
            sb_str = rest_api._generate_singbox_config(fake_user)
        sb = json.loads(sb_str)
        # Ключа _snell_compat_note не должно быть в JSON.
        self.assertNotIn("_snell_compat_note", sb,
                         "Ключ _snell_compat_note не должен появляться "
                         "без активного Snell")


class TestSingboxSnellCompatNote(unittest.TestCase):
    """Тесты для информационного поля _snell_compat_note в sing-box JSON.

    Контракт (см. задачу):
      • Когда Snell outbound реально добавлен в config["outbounds"] —
        в JSON должно быть поле "_snell_compat_note" с непустой строкой.
      • Когда Snell не установлен / не активен / нет матчинга пользователя —
        ключа _snell_compat_note не должно быть ВООБЩЕ (не пустая строка,
        а отсутствие ключа).
      • Формат JSON — indent=2, ensure_ascii=False (как и раньше).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _fake_snell_outbound(self):
        """Возвращает mock snell outbound dict (как get_user_singbox_outbound)."""
        return {
            "type": "snell",
            "tag": "snell-out",
            "server": "test.example.com",
            "server_port": 30001,
            "password": "dGVzdHBzaw==",
            "obfs": {"type": "tls", "host": "test.example.com"},
        }

    def _patch_snell_active_with_user(self, username="alice"):
        """Патчит snell.is_any_active → True и get_user_singbox_outbound →
        возвращает fake outbound для указанного username."""
        from chimera.modules import snell
        # ВАЖНО: patch.object нужно применять к модулю snell, а в rest_api
        # импорт происходит через `from chimera.modules.snell import ...`.
        # Поэтому патчим исходный модуль — rest_api увидит изменения.
        def fake_get_outbound(name, server_ip=""):
            if name == username:
                return self._fake_snell_outbound()
            return None
        return [
            patch.object(snell, "is_any_active", return_value=True),
            patch.object(snell, "get_user_singbox_outbound",
                         side_effect=fake_get_outbound),
        ]

    def _fake_state(self):
        return {
            "domain": "test.example.com", "server_port": 443,
            "protocol_mode": "reality", "public_key": "p", "short_id": "s",
            "fingerprint": "chrome", "xtls_flow": "xtls-rprx-vision",
        }

    def test_compat_note_present_when_snell_active(self):
        """Когда Snell-outbound добавлен в конфиг — _snell_compat_note
        должна быть непустой строкой."""
        from chimera.modules import rest_api
        patches = self._patch_snell_active_with_user("alice")
        for p in patches:
            p.start()
        try:
            with patch.object(rest_api, "_get_state",
                              return_value=self._fake_state()):
                fake_user = {"uuid": "u1", "name": "alice",
                             "email": "alice@x.com"}
                sb_str = rest_api._generate_singbox_config(fake_user)
        finally:
            for p in patches:
                p.stop()
        sb = json.loads(sb_str)
        # Snell-outbound должен быть в outbounds.
        snell_obs = [o for o in sb["outbounds"] if o.get("type") == "snell"]
        self.assertEqual(len(snell_obs), 1,
                         "Snell outbound должен быть в конфиге")
        # _snell_compat_note должен быть непустой строкой.
        self.assertIn("_snell_compat_note", sb,
                      "Ключ _snell_compat_note должен быть в JSON когда "
                      "Snell-outbound добавлен")
        note = sb["_snell_compat_note"]
        self.assertIsInstance(note, str)
        self.assertGreater(len(note), 50,
                           "Заметка должна быть содержательной (не пустая)")

    def test_compat_note_absent_when_snell_module_missing(self):
        """Если snell-модуль не импортируется (ImportError) — _snell_compat_note
        не должно быть в JSON, и VLESS-outbound должен остаться."""
        from chimera.modules import rest_api
        # Прячем snell-модуль из sys.modules.
        real = sys.modules.get("chimera.modules.snell")
        sys.modules.pop("chimera.modules.snell", None)
        # Подменяем на модуль без нужных атрибутов → ImportError при импорте.
        broken = type(sys)("chimera.modules.snell")
        sys.modules["chimera.modules.snell"] = broken
        try:
            with patch.object(rest_api, "_get_state",
                              return_value=self._fake_state()):
                fake_user = {"uuid": "u1", "name": "alice"}
                sb_str = rest_api._generate_singbox_config(fake_user)
        finally:
            if real is not None:
                sys.modules["chimera.modules.snell"] = real
            else:
                sys.modules.pop("chimera.modules.snell", None)
        sb = json.loads(sb_str)
        # VLESS-outbound должен остаться (не сломался).
        self.assertGreater(len(sb["outbounds"]), 0)
        self.assertEqual(sb["outbounds"][0]["type"], "vless")
        # Snell-outbound-ов нет.
        snell_obs = [o for o in sb["outbounds"] if o.get("type") == "snell"]
        self.assertEqual(len(snell_obs), 0)
        # _snell_compat_note отсутствует.
        self.assertNotIn("_snell_compat_note", sb)

    def test_compat_note_absent_when_snell_inactive(self):
        """Если snell.is_any_active() возвращает False — _snell_compat_note
        отсутствует (даже если модуль импортируется)."""
        from chimera.modules import rest_api, snell
        with patch.object(snell, "is_any_active", return_value=False), \
             patch.object(rest_api, "_get_state",
                          return_value=self._fake_state()):
            fake_user = {"uuid": "u1", "name": "alice"}
            sb_str = rest_api._generate_singbox_config(fake_user)
        sb = json.loads(sb_str)
        # Snell outbound-ов нет.
        snell_obs = [o for o in sb["outbounds"] if o.get("type") == "snell"]
        self.assertEqual(len(snell_obs), 0)
        # _snell_compat_note отсутствует.
        self.assertNotIn("_snell_compat_note", sb)

    def test_compat_note_absent_when_user_not_matched(self):
        """Если Snell активен, но у юзера нет соответствующего аккаунта —
        _snell_compat_note отсутствует ( outbound не добавлен)."""
        from chimera.modules import rest_api, snell
        # Snell активен, но get_user_singbox_outbound возвращает None
        # для всех кандидатов (юзер не найден).
        with patch.object(snell, "is_any_active", return_value=True), \
             patch.object(snell, "get_user_singbox_outbound",
                          return_value=None), \
             patch.object(rest_api, "_get_state",
                          return_value=self._fake_state()):
            fake_user = {"uuid": "u1", "name": "unknown_user",
                         "email": "nobody@nowhere.com"}
            sb_str = rest_api._generate_singbox_config(fake_user)
        sb = json.loads(sb_str)
        # Snell outbound-ов нет (нет матчинга).
        snell_obs = [o for o in sb["outbounds"] if o.get("type") == "snell"]
        self.assertEqual(len(snell_obs), 0)
        # _snell_compat_note отсутствует.
        self.assertNotIn("_snell_compat_note", sb)

    def test_compat_note_mentions_official_singbox_incompatibility(self):
        """Текст заметки должен явно упоминать что официальный sing-box
        не поддерживает Snell."""
        from chimera.modules import rest_api, snell
        patches = self._patch_snell_active_with_user("alice")
        for p in patches:
            p.start()
        try:
            with patch.object(rest_api, "_get_state",
                              return_value=self._fake_state()):
                fake_user = {"uuid": "u1", "name": "alice"}
                sb_str = rest_api._generate_singbox_config(fake_user)
        finally:
            for p in patches:
                p.stop()
        sb = json.loads(sb_str)
        note = sb["_snell_compat_note"]
        # Проверяем ключевые слова, которые должны быть в заметке.
        self.assertIn("sing-box", note.lower())
        # Должно упоминать "официальн" (официальный/официальная).
        self.assertIn("официальн", note.lower())
        # Должно упоминать форки — Dress или sss-box-shadow.
        self.assertTrue("Dress" in note or "sss-box-shadow" in note,
                        "Заметка должна упоминать форки (Dress/sss-box-shadow)")

    def test_compat_note_in_indent2_json(self):
        """JSON должен быть с indent=2 (как и раньше)."""
        from chimera.modules import rest_api, snell
        patches = self._patch_snell_active_with_user("alice")
        for p in patches:
            p.start()
        try:
            with patch.object(rest_api, "_get_state",
                              return_value=self._fake_state()):
                fake_user = {"uuid": "u1", "name": "alice"}
                sb_str = rest_api._generate_singbox_config(fake_user)
        finally:
            for p in patches:
                p.stop()
        # Проверяем что в JSON есть отступы (indent=2 → "\n  ").
        self.assertIn("\n  ", sb_str,
                      "JSON должен быть с indent=2 (многострочный)")
        # Должен парситься обратно в тот же dict.
        sb = json.loads(sb_str)
        self.assertIn("_snell_compat_note", sb)


class TestSubscriptionIntegration(unittest.TestCase):
    """Интеграционный тест: _build_snell_uris не падает без Snell."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_build_snell_uris_returns_empty_when_not_installed(self):
        from chimera.modules.subscription import _build_snell_uris
        user = {"name": "alice", "email": "alice@x.com"}
        result = _build_snell_uris(user, "1.2.3.4")
        self.assertEqual(result, [])


class TestStatusPanelIntegration(unittest.TestCase):
    """Интеграционный тест: status_panel._check_snell() не падает."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_check_snell_returns_false_in_test_env(self):
        from chimera.modules.status_panel import _check_snell
        # В тестовой среде Snell не установлен — должно быть False.
        self.assertFalse(_check_snell())

    def test_check_snell_in_protocol_checks_list(self):
        """Snell должен быть в списке _protocol_checks()."""
        from chimera.modules.status_panel import _protocol_checks
        checks = _protocol_checks({})
        names = [name for name, _ in checks]
        self.assertIn("Snell v4", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
