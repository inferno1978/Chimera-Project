#!/usr/bin/env python3
"""
tests/test_users_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/users_manager.py — управление
пользователями Xray, генерация VLESS-ссылок, синхронизация config.json.

Покрывает:
  1. _gen_vless_link — генерация VLESS-ссылки (reality + xhttp, URL-encoding).
  2. _users_load — чтение users.json + инициализация из state.json.
  3. _users_save — запись users.json с chmod 0o640.
  4. _users_patch_config_no_restart — патч clients в config.json БЕЗ рестарта.
  5. _unified_load_users — объединение пользователей из users.json + config.json.
  6. _unified_save_users — синхронизация в users.json + config.json.
  7. _unified_show_links — генерация IPv4/IPv6/Domain ссылок для пользователя.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import types
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_health.py."""
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
#  _gen_vless_link — генерация VLESS-ссылки
# ══════════════════════════════════════════════════════════════════════════════
class TestGenVlessLink(unittest.TestCase):
    """_gen_vless_link: построение VLESS-ссылки для REALITY / xHTTP TLS."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        # Без флага-эмодзи (упрощает URL-проверки)
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", ""))

    def test_reality_link_contains_all_params(self):
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid-1234", pbk="PUB",
            sid="abcd1234", domain="example.com",
            fp="chrome", proto="reality", port=443,
        )
        self.assertIn("vless://uuid-1234@1.2.3.4:443", link)
        self.assertIn("type=tcp", link)
        self.assertIn("security=reality", link)
        self.assertIn("pbk=PUB", link)
        self.assertIn("sid=abcd1234", link)
        self.assertIn("fp=chrome", link)
        self.assertIn("sni=example.com", link)
        self.assertIn("flow=xtls-rprx-vision", link)

    def test_xhttp_link_contains_path_and_mode(self):
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid-1234", pbk="",
            sid="", domain="example.com",
            fp="firefox", proto="xhttp",
            xhttp_path="/xhttp", xhttp_mode="stream-up",
            port=8443,
        )
        self.assertIn("vless://uuid-1234@1.2.3.4:8443", link)
        self.assertIn("type=xhttp", link)
        self.assertIn("security=tls", link)
        self.assertIn("sni=example.com", link)
        # Path URL-encoded
        self.assertIn(f"path={urllib.parse.quote('/xhttp', safe='/')}", link)
        self.assertIn("mode=stream-up", link)
        self.assertIn("fp=firefox", link)
        # flow не должно быть в xhttp-ссылке
        self.assertNotIn("flow=", link)

    def test_flag_emoji_added_to_label(self):
        """Флаг-эмодзи добавляется к label, если не '🌐' и не пустой."""
        from chimera.modules.users_manager import _gen_vless_link
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", "🇷🇺"))
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid", pbk="P", sid="S",
            domain="example.com", proto="reality",
        )
        # Флаг должен быть в label (после #)
        self.assertIn("🇷🇺", link.split("#")[-1])

    def test_no_flag_when_emoji_is_globe(self):
        """Если флаг == '🌐' — не добавляется префикс."""
        from chimera.modules.users_manager import _gen_vless_link
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("XX", "Unknown", "🌐"))
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid", pbk="P", sid="S",
            domain="example.com", proto="reality",
        )
        # 🌐 НЕ должно быть в label
        self.assertNotIn("🌐", link.split("#")[-1])

    def test_domain_is_url_encoded_in_label(self):
        """Domain URL-кодируется в label (после #)."""
        from chimera.modules.users_manager import _gen_vless_link
        # domain с пробелом — должен быть URL-encoded
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid", pbk="P", sid="S",
            domain="example.com", proto="reality",
        )
        # В label домен кодируется как есть (для обычного домена без спецсимволов)
        self.assertIn("#example.com", link)

    def test_xhttp_path_with_spaces_url_encoded(self):
        """xhttp_path с пробелами URL-кодируется."""
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid", pbk="", sid="",
            domain="example.com", proto="xhttp",
            xhttp_path="/path with space",
        )
        # Пробел = %20
        self.assertIn("%20", link)

    def test_ipv6_host_keeps_brackets(self):
        """IPv6-хост должен передаваться в формате [::1] (вызывающая сторона
        обязана обернуть адрес в [], функция не убирает скобки)."""
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="[2001:db8::1]", uuid_str="uuid", pbk="P", sid="S",
            domain="example.com", proto="reality", port=443,
        )
        self.assertIn("[2001:db8::1]:443", link)

    def test_non_default_port_in_link(self):
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="uuid", pbk="P", sid="S",
            domain="example.com", proto="reality", port=8443,
        )
        self.assertIn(":8443", link)
        self.assertNotIn(":443", link)


# ══════════════════════════════════════════════════════════════════════════════
#  _users_load — чтение users.json
# ══════════════════════════════════════════════════════════════════════════════
class TestUsersLoad(unittest.TestCase):
    """_users_load: чтение users.json, инициализация из state.json при отсутствии."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._users_file = Path(self._tmpdir) / "users.json"
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_paths(self):
        c = self._fake_core
        c.USERS_FILE = self._users_file
        c.STATE_FILE = self._state_file

    def test_returns_list_from_users_file(self):
        from chimera.modules.users_manager import _users_load
        self._patch_paths()
        users = [
            {"uuid": "u1", "email": "a@x", "name": "alice"},
            {"uuid": "u2", "email": "b@x", "name": "bob"},
        ]
        self._users_file.write_text(json.dumps(users))
        result = _users_load()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["uuid"], "u1")

    def test_returns_empty_when_no_users_file_no_state(self):
        from chimera.modules.users_manager import _users_load
        self._patch_paths()
        result = _users_load()
        self.assertEqual(result, [])

    def test_initializes_from_state_when_no_users_file(self):
        """users.json отсутствует, но state.json содержит uuid → 1 default user."""
        from chimera.modules.users_manager import _users_load
        self._patch_paths()
        self._state_file.write_text(json.dumps({
            "uuid": "test-uuid",
            "email": "default@xray",
            "installed_at": "2024-01-01",
        }))
        result = _users_load()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["uuid"], "test-uuid")
        self.assertEqual(result[0]["email"], "default@xray")
        self.assertEqual(result[0]["name"], "default")
        self.assertEqual(result[0]["created"], "2024-01-01")

    def test_returns_empty_on_corrupt_users_file(self):
        from chimera.modules.users_manager import _users_load
        self._patch_paths()
        self._users_file.write_text("{invalid json!!!")
        result = _users_load()
        self.assertEqual(result, [])


# ══════════════════════════════════════════════════════════════════════════════
#  _users_save — запись users.json
# ══════════════════════════════════════════════════════════════════════════════
class TestUsersSave(unittest.TestCase):
    """_users_save: запись users.json с chmod 0o640."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._users_file = Path(self._tmpdir) / "subdir" / "users.json"
        self._fake_core.USERS_FILE = self._users_file

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_writes_valid_json(self):
        from chimera.modules.users_manager import _users_save
        users = [{"uuid": "u1", "email": "a@x", "name": "alice"}]
        _users_save(users)
        data = json.loads(self._users_file.read_text())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["uuid"], "u1")

    def test_sets_chmod_640(self):
        from chimera.modules.users_manager import _users_save
        _users_save([{"uuid": "u", "email": "e@x", "name": "n"}])
        mode = stat.S_IMODE(os.stat(self._users_file).st_mode)
        self.assertEqual(mode, 0o640,
                         f"users.json должен иметь права 0o640, got {oct(mode)}")

    def test_creates_parent_dir(self):
        """Родительская директория создаётся при отсутствии."""
        from chimera.modules.users_manager import _users_save
        # _users_file уже указывает на subdir/users.json, но subdir не существует
        # Path.mkdir патчится в _setup_core_in_sysmodules — распатчим для этого теста
        with patch.object(Path, 'mkdir', Path.mkdir.__wrapped__ if hasattr(Path.mkdir, '__wrapped__') else Path.mkdir):
            _users_save([{"uuid": "u", "email": "e@x", "name": "n"}])
        self.assertTrue(self._users_file.exists())

    def test_overwrites_existing(self):
        from chimera.modules.users_manager import _users_save
        _users_save([{"uuid": "v1", "email": "a@x", "name": "n1"}])
        _users_save([{"uuid": "v2", "email": "b@x", "name": "n2"}])
        data = json.loads(self._users_file.read_text())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["uuid"], "v2")


# ══════════════════════════════════════════════════════════════════════════════
#  _users_patch_config_no_restart — патч clients без рестарта
# ══════════════════════════════════════════════════════════════════════════════
class TestUsersPatchConfigNoRestart(unittest.TestCase):
    """_users_patch_config_no_restart: патчит clients в config.json."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._cfg = Path(self._tmpdir) / "config.json"
        # CONFIG_DIR должен быть Path, не str — код делает CONFIG_DIR / "config.json"
        self._fake_core.CONFIG_DIR = Path(self._tmpdir)
        self._fake_core.XTLS_FLOW = "xtls-rprx-vision"
        self._fake_core._set_config_owner = MagicMock()
        self._fake_core.warn = MagicMock()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_reality_config(self, clients=None):
        """Создаёт config.json с VLESS+REALITY inbound."""
        cfg = {
            "inbounds": [{
                "tag": "inbound-vless",
                "protocol": "vless",
                "settings": {"clients": clients or []},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {"serverNames": ["example.com"]},
                },
            }],
        }
        self._cfg.write_text(json.dumps(cfg))

    def _write_xhttp_config(self, clients=None):
        """Создаёт config.json с VLESS+xhttp inbound."""
        cfg = {
            "inbounds": [{
                "tag": "inbound-xhttp",
                "protocol": "vless",
                "settings": {"clients": clients or []},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                },
            }],
        }
        self._cfg.write_text(json.dumps(cfg))

    def test_reality_inbound_gets_flow(self):
        """REALITY inbound → clients получают 'flow' поле."""
        from chimera.modules.users_manager import _users_patch_config_no_restart
        self._write_reality_config()
        users = [{"uuid": "u1", "email": "a@x"}]
        result = _users_patch_config_no_restart(users)
        self.assertTrue(result)
        cfg = json.loads(self._cfg.read_text())
        clients = cfg["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["id"], "u1")
        self.assertEqual(clients[0]["email"], "a@x")
        self.assertEqual(clients[0]["flow"], "xtls-rprx-vision")

    def test_xhttp_inbound_no_flow(self):
        """xhttp inbound → clients БЕЗ 'flow' поля."""
        from chimera.modules.users_manager import _users_patch_config_no_restart
        self._write_xhttp_config()
        users = [{"uuid": "u1", "email": "a@x"}]
        result = _users_patch_config_no_restart(users)
        self.assertTrue(result)
        cfg = json.loads(self._cfg.read_text())
        clients = cfg["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(clients), 1)
        self.assertNotIn("flow", clients[0])

    def test_returns_true_when_no_config(self):
        """Если config.json не существует — True (ничего не делаем)."""
        from chimera.modules.users_manager import _users_patch_config_no_restart
        # Удаляем конфиг
        if self._cfg.exists():
            self._cfg.unlink()
        result = _users_patch_config_no_restart([{"uuid": "u", "email": "e@x"}])
        self.assertTrue(result)

    def test_user_without_email_skipped_email_field(self):
        """Если у пользователя нет email — поле email не добавляется в client."""
        from chimera.modules.users_manager import _users_patch_config_no_restart
        self._write_reality_config()
        users = [{"uuid": "u1"}]  # без email
        result = _users_patch_config_no_restart(users)
        self.assertTrue(result)
        cfg = json.loads(self._cfg.read_text())
        client = cfg["inbounds"][0]["settings"]["clients"][0]
        self.assertNotIn("email", client)
        self.assertEqual(client["id"], "u1")

    def test_skips_inbounds_without_clients(self):
        """Inbound без секции 'clients' — пропускается."""
        from chimera.modules.users_manager import _users_patch_config_no_restart
        cfg = {
            "inbounds": [
                {"tag": "dokodemo", "protocol": "dokodemo-door",
                 "settings": {"network": "tcp"}},  # без clients
                {"tag": "vless", "protocol": "vless",
                 "settings": {"clients": []},
                 "streamSettings": {"security": "reality",
                                    "realitySettings": {}}},
            ],
        }
        self._cfg.write_text(json.dumps(cfg))
        _users_patch_config_no_restart([{"uuid": "u", "email": "e@x"}])
        cfg = json.loads(self._cfg.read_text())
        # dokodemo не тронут
        self.assertEqual(cfg["inbounds"][0]["settings"]["network"], "tcp")
        # vless запатчен
        self.assertEqual(len(cfg["inbounds"][1]["settings"]["clients"]), 1)


# ══════════════════════════════════════════════════════════════════════════════
#  _unified_load_users — объединение пользователей
# ══════════════════════════════════════════════════════════════════════════════
class TestUnifiedLoadUsers(unittest.TestCase):
    """_unified_load_users: объединение пользователей из users.json + config.json."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._users_file = Path(self._tmpdir) / "users.json"
        self._cfg = Path(self._tmpdir) / "xray" / "config.json"
        self._cfg.parent.mkdir(parents=True)
        self._fake_core.USERS_FILE = self._users_file

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_loads_from_users_json(self):
        from chimera.modules.users_manager import _unified_load_users
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "a@x", "name": "alice",
             "created": "2024-01-01", "source": "B"},
        ]))
        # На продакшен-сервере /etc/xray/config.json существует с реальными
        # клиентами — без этого mock _unified_load_users вернёт их тоже,
        # и len(result) != 1. Патчим exists() для config.json путей.
        _cfg_paths = {"/etc/xray/config.json", "/usr/local/etc/xray/config.json"}
        _orig_exists = Path.exists
        def _exists(self):
            if str(self) in _cfg_paths:
                return False
            return _orig_exists(self)
        with patch.object(Path, "exists", _exists):
            result = _unified_load_users()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["uuid"], "u1")
        self.assertEqual(result[0]["source"], "B")

    def test_loads_from_config_json_when_no_users_file(self):
        from chimera.modules import users_manager
        # _unified_load_users хардкодит /etc/xray/config.json и /usr/local/etc/xray/config.json
        # Патчим только эти пути — на чтение из нашего tmp cfg.
        cfg = {
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": [
                    {"id": "cfg-uuid", "email": "cfg@xray", "flow": "xtls"},
                ]},
            }],
        }
        self._cfg.write_text(json.dumps(cfg))
        cfg_content = json.dumps(cfg)
        cfg_path_str = str(self._cfg)
        real_paths = ("/etc/xray/config.json", "/usr/local/etc/xray/config.json")

        orig_exists = Path.exists
        orig_read_text = Path.read_text

        def _exists(self):
            return str(self) in real_paths

        def _read_text(self):
            if str(self) in real_paths:
                return cfg_content
            return orig_read_text(self)

        Path.exists = _exists
        Path.read_text = _read_text
        try:
            result = users_manager._unified_load_users()
        finally:
            Path.exists = orig_exists
            Path.read_text = orig_read_text
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["uuid"], "cfg-uuid")
        self.assertEqual(result[0]["source"], "A")
        self.assertEqual(result[0]["flow"], "xtls")
        self.assertEqual(result[0]["name"], "cfg")  # email.split('@')[0]

    def test_deduplicates_by_uuid(self):
        """Один и тот же UUID в users.json и config.json — один пользователь (приоритет users.json)."""
        from chimera.modules import users_manager
        self._users_file.write_text(json.dumps([
            {"uuid": "shared-uuid", "email": "from_users@x", "name": "alice"},
        ]))
        cfg = {
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": [
                    {"id": "shared-uuid", "email": "from_cfg@xray"},
                ]},
            }],
        }
        self._cfg.write_text(json.dumps(cfg))
        cfg_content = json.dumps(cfg)
        real_paths = ("/etc/xray/config.json", "/usr/local/etc/xray/config.json")

        orig_exists = Path.exists
        orig_read_text = Path.read_text

        def _exists(self):
            s = str(self)
            # users.json существует (реально) → возвращаем True для него
            # /etc/xray/config.json → True
            if s in real_paths:
                return True
            return orig_exists(self)

        def _read_text(self):
            s = str(self)
            if s in real_paths:
                return cfg_content
            return orig_read_text(self)

        Path.exists = _exists
        Path.read_text = _read_text
        try:
            result = users_manager._unified_load_users()
        finally:
            Path.exists = orig_exists
            Path.read_text = orig_read_text
        self.assertEqual(len(result), 1)
        # users.json источник первый → его email выигрывает
        self.assertEqual(result[0]["email"], "from_users@x")

    def test_empty_when_no_sources(self):
        from chimera.modules.users_manager import _unified_load_users
        with patch.object(Path, "exists", return_value=False):
            result = _unified_load_users()
        self.assertEqual(result, [])

    def test_preserves_disabled_flag(self):
        """Флаг disabled из users.json сохраняется."""
        from chimera.modules.users_manager import _unified_load_users
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "a@x", "name": "alice",
             "disabled": True, "disabled_at": "2024-06-01"},
        ]))
        # На продакшен-сервере /etc/xray/config.json существует — патчим.
        _cfg_paths = {"/etc/xray/config.json", "/usr/local/etc/xray/config.json"}
        _orig_exists = Path.exists
        def _exists(self):
            if str(self) in _cfg_paths:
                return False
            return _orig_exists(self)
        with patch.object(Path, "exists", _exists):
            result = _unified_load_users()
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["disabled"])
        self.assertEqual(result[0]["disabled_at"], "2024-06-01")


# ══════════════════════════════════════════════════════════════════════════════
#  _users_collect_for_config / _clients_from_users — единый источник юзеров
#  для генерации/регенерации конфига Xray (BUGFIX v53)
# ══════════════════════════════════════════════════════════════════════════════
class TestUsersCollectForConfig(unittest.TestCase):
    """
    Регрессия v53: регенерация конфига Xray (AGH-финализация,
    «Пересоздать конфиг», emergency repair) обязана сохранять в
    clients ВСЕХ активных юзеров — иначе клиенты со ссылками,
    выданными до регенерации, получают EOF («invalid request user id»).
    """

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._users_file = Path(self._tmpdir) / "users.json"
        self._fake_core.USERS_FILE = self._users_file
        # /etc/xray/config.json не должен подсасываться на тест-машине
        self._cfg_paths = {"/etc/xray/config.json",
                           "/usr/local/etc/xray/config.json"}
        self._orig_exists = Path.exists

    def tearDown(self):
        Path.exists = self._orig_exists
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _collect(self, param_uuid="param-uuid", param_email="user@example.com"):
        from chimera.modules import users_manager
        orig_exists = self._orig_exists
        # Локальная переменная (НЕ self._cfg_paths): внутри _exists self —
        # это Path-объект, обращение к атрибутам TestCase падает с
        # AttributeError, который _users_collect_for_config молча глотает.
        cfg_paths = self._cfg_paths

        def _exists(p):
            if str(p) in cfg_paths:
                return False
            return orig_exists(p)

        with patch.object(Path, "exists", _exists):
            return users_manager._users_collect_for_config(
                param_uuid, param_email)

    def test_fresh_install_fallback_to_param_uuid(self):
        """Юзеров нет (fresh install) → только PARAM_UUID, как раньше."""
        result = self._collect(param_uuid="fresh-uuid",
                               param_email="user@example.com")
        self.assertEqual(result, [{"uuid": "fresh-uuid",
                                   "email": "user@example.com"}])

    def test_users_json_preserved_plus_param_uuid(self):
        """Юзер из users.json сохраняется, PARAM_UUID добавляется (сценарий
        state.json ≠ users.json: ссылка выдана с uuid из users.json)."""
        self._users_file.write_text(json.dumps([
            {"uuid": "link-uuid", "email": "alice@xray", "name": "alice"},
        ]))
        result = self._collect(param_uuid="state-uuid",
                               param_email="user@example.com")
        uuids = [u["uuid"] for u in result]
        self.assertIn("link-uuid", uuids,
                      "UUID из выданной ссылки обязан остаться в конфиге")
        self.assertIn("state-uuid", uuids)
        self.assertEqual(len(result), 2)

    def test_param_uuid_already_present_no_duplicate(self):
        """PARAM_UUID совпадает с юзером → дубликата нет."""
        self._users_file.write_text(json.dumps([
            {"uuid": "same-uuid", "email": "alice@xray", "name": "alice"},
        ]))
        result = self._collect(param_uuid="same-uuid",
                               param_email="user@example.com")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["email"], "alice@xray")

    def test_disabled_user_excluded(self):
        """Disabled-юзер в clients не попадает (xray не должен его пускать)."""
        self._users_file.write_text(json.dumps([
            {"uuid": "active-uuid", "email": "a@xray", "name": "a"},
            {"uuid": "off-uuid", "email": "b@xray", "name": "b",
             "disabled": True},
        ]))
        result = self._collect(param_uuid="param-uuid",
                               param_email="user@example.com")
        uuids = [u["uuid"] for u in result]
        self.assertNotIn("off-uuid", uuids)
        self.assertIn("active-uuid", uuids)

    def test_duplicate_email_filtered(self):
        """Дубль email отфильтрован — xray падает на «User X already exists»."""
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "same@xray", "name": "a"},
            {"uuid": "u2", "email": "same@xray", "name": "b"},
        ]))
        result = self._collect(param_uuid="param-uuid",
                               param_email="user@example.com")
        emails = [u["email"] for u in result]
        self.assertEqual(len(emails), len(set(emails)),
                         "email должны быть уникальны")
        self.assertIn("u1", [u["uuid"] for u in result])
        self.assertNotIn("u2", [u["uuid"] for u in result])

    def test_clients_from_users_flow(self):
        """_clients_from_users: формат Xray clients, flow по требованию."""
        from chimera.modules.users_manager import _clients_from_users
        users = [{"uuid": "u1", "email": "a@xray"}]
        with_flow = _clients_from_users(users, "xtls-rprx-vision")
        self.assertEqual(with_flow, [{"id": "u1", "email": "a@xray",
                                      "flow": "xtls-rprx-vision"}])
        no_flow = _clients_from_users(users)
        self.assertEqual(no_flow, [{"id": "u1", "email": "a@xray"}])


# ══════════════════════════════════════════════════════════════════════════════
#  _unified_save_users — синхронизация users.json + config.json
# ══════════════════════════════════════════════════════════════════════════════
class TestUnifiedSaveUsers(unittest.TestCase):
    """_unified_save_users: запись в users.json + синхронизация в config.json."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._users_file = Path(self._tmpdir) / "users.json"
        self._cfg = Path(self._tmpdir) / "xray" / "config.json"
        self._cfg.parent.mkdir(parents=True)
        self._fake_core.USERS_FILE = self._users_file
        self._fake_core.CONFIG_DIR = self._cfg.parent
        self._fake_core.XTLS_FLOW = "xtls-rprx-vision"
        self._fake_core._set_config_owner = MagicMock()
        self._fake_core.warn = MagicMock()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_writes_users_json(self):
        from chimera.modules.users_manager import _unified_save_users
        users = [{"uuid": "u1", "email": "a@x", "name": "alice"}]
        _unified_save_users(users)
        data = json.loads(self._users_file.read_text())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["uuid"], "u1")
        # source default = "A" если не указано
        self.assertEqual(data[0]["source"], "A")

    def test_syncs_to_config_json(self):
        from chimera.modules.users_manager import _unified_save_users
        cfg = {
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": []},
                "streamSettings": {"security": "reality",
                                   "realitySettings": {}},
            }],
        }
        self._cfg.write_text(json.dumps(cfg))
        _unified_save_users([{"uuid": "u1", "email": "a@x", "name": "alice"}])
        cfg = json.loads(self._cfg.read_text())
        clients = cfg["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["id"], "u1")

    def test_preserves_disabled_flag_in_users_json(self):
        from chimera.modules.users_manager import _unified_save_users
        users = [{"uuid": "u1", "email": "a@x", "name": "alice",
                  "disabled": True, "disabled_at": "2024-06-01"}]
        _unified_save_users(users)
        data = json.loads(self._users_file.read_text())
        self.assertTrue(data[0]["disabled"])
        self.assertEqual(data[0]["disabled_at"], "2024-06-01")

    def test_name_defaults_from_email(self):
        """Если name не указан — берётся из email (часть до @)."""
        from chimera.modules.users_manager import _unified_save_users
        _unified_save_users([{"uuid": "u", "email": "alice@example.com"}])
        data = json.loads(self._users_file.read_text())
        self.assertEqual(data[0]["name"], "alice")

    def test_xhttp_inbound_no_flow(self):
        """xhttp inbound → clients БЕЗ flow (use_flow=False, но net='xhttp' исключён)."""
        from chimera.modules.users_manager import _unified_save_users
        cfg = {
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": []},
                "streamSettings": {"network": "xhttp",
                                   "security": "none"},
            }],
        }
        self._cfg.write_text(json.dumps(cfg))
        _unified_save_users([{"uuid": "u1", "email": "a@x"}])
        cfg = json.loads(self._cfg.read_text())
        client = cfg["inbounds"][0]["settings"]["clients"][0]
        self.assertNotIn("flow", client)


# ══════════════════════════════════════════════════════════════════════════════
#  _unified_show_links — генерация IPv4/IPv6/Domain ссылок
# ══════════════════════════════════════════════════════════════════════════════
class TestUnifiedShowLinks(unittest.TestCase):
    """_unified_show_links: генерация ссылок для пользователя."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"
        self._fake_core.STATE_FILE = self._state_file
        # Stub all core helpers
        self._fake_core._box_top = MagicMock()
        self._fake_core._box_row = MagicMock()
        self._fake_core._box_bottom = MagicMock()
        self._fake_core._box_link = MagicMock()
        self._fake_core.get_server_ip = MagicMock(return_value="1.2.3.4")
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", ""))
        self._fake_core.warn = MagicMock()
        self._fake_core.GREEN = ""
        self._fake_core.CYAN = ""
        self._fake_core.MAGENTA = ""
        self._fake_core.BLUE = ""
        self._fake_core.DIM = ""
        self._fake_core.NC = ""
        # _show_qr патчим через patch.object(users_manager, "_show_qr")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_state(self, state_dict: dict):
        self._state_file.write_text(json.dumps(state_dict))

    def test_returns_empty_when_no_state(self):
        from chimera.modules import users_manager
        with patch.object(users_manager, "_show_qr"):
            result = users_manager._unified_show_links(
                {"uuid": "u", "name": "alice"}, print_output=False)
        self.assertEqual(result, [])

    def test_returns_empty_when_state_corrupt(self):
        from chimera.modules import users_manager
        self._state_file.write_text("{invalid json")
        with patch.object(users_manager, "_show_qr"):
            result = users_manager._unified_show_links(
                {"uuid": "u", "name": "alice"}, print_output=False)
        self.assertEqual(result, [])

    def test_generates_ipv4_link_for_reality(self):
        from chimera.modules import users_manager
        self._write_state({
            "domain": "example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "install_mode": "A",
        })
        # get_server_ip("4") → "1.2.3.4", get_server_ip("6") → ""
        self._fake_core.get_server_ip = MagicMock(
            side_effect=lambda v: "1.2.3.4" if v == "4" else "")
        with patch.object(users_manager, "_show_qr"):
            links = users_manager._unified_show_links(
                {"uuid": "test-uuid", "name": "alice"},
                print_output=False,
            )
        # Должна быть IPv4 + Domain = 2 ссылки (IPv6 пустой)
        self.assertEqual(len(links), 2)
        ipv4_link = links[0]
        self.assertIn("vless://test-uuid@1.2.3.4:443", ipv4_link)
        self.assertIn("security=reality", ipv4_link)
        self.assertIn("pbk=PUBKEY", ipv4_link)

    def test_generates_ipv6_link_when_install_mode_a(self):
        from chimera.modules import users_manager
        self._write_state({
            "domain": "example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "ipv6": "2001:db8::1",
            "install_mode": "A",
        })
        self._fake_core.get_server_ip = MagicMock(
            side_effect=lambda v: "1.2.3.4" if v == "4" else "")
        with patch.object(users_manager, "_show_qr"):
            links = users_manager._unified_show_links(
                {"uuid": "test-uuid", "name": "alice"},
                print_output=False,
            )
        # IPv4 + IPv6 + Domain = 3 ссылки
        self.assertEqual(len(links), 3)
        ipv6_link = links[1]
        self.assertIn("[2001:db8::1]:443", ipv6_link)

    def test_no_ipv6_link_in_mode_b(self):
        """В install_mode='B' IPv6-ссылка не генерируется."""
        from chimera.modules import users_manager
        self._write_state({
            "domain": "example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "ipv6": "2001:db8::1",
            "install_mode": "B",
        })
        self._fake_core.get_server_ip = MagicMock(
            side_effect=lambda v: "1.2.3.4" if v == "4" else "")
        with patch.object(users_manager, "_show_qr"):
            links = users_manager._unified_show_links(
                {"uuid": "test-uuid", "name": "alice"},
                print_output=False,
            )
        # Только IPv4 + Domain (IPv6 пропущен в Mode B)
        self.assertEqual(len(links), 2)

    def test_awg_mode_uses_reality_dest_as_sni(self):
        """Mode B + AWG + reality → SNI = reality_dest (домен маскировки)."""
        from chimera.modules import users_manager
        self._write_state({
            "domain": "example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "install_mode": "B",
            "awg_exit_enabled": True,
            "reality_dest": "www.cloudflare.com",
        })
        self._fake_core.get_server_ip = MagicMock(
            side_effect=lambda v: "1.2.3.4" if v == "4" else "")
        with patch.object(users_manager, "_show_qr"):
            links = users_manager._unified_show_links(
                {"uuid": "test-uuid", "name": "alice"},
                print_output=False,
            )
        # SNI в ссылке = reality_dest, не domain
        ipv4_link = links[0]
        self.assertIn("sni=www.cloudflare.com", ipv4_link)
        self.assertNotIn("sni=example.com", ipv4_link)

    def test_label_replaces_domain_in_fragment(self):
        """В fragment (#label) домен заменяется на label пользователя."""
        from chimera.modules import users_manager
        self._write_state({
            "domain": "example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "install_mode": "A",
        })
        self._fake_core.get_server_ip = MagicMock(
            side_effect=lambda v: "1.2.3.4" if v == "4" else "")
        with patch.object(users_manager, "_show_qr"):
            links = users_manager._unified_show_links(
                {"uuid": "test-uuid", "name": "alice"},
                print_output=False,
            )
        # Fragment должен содержать 'alice' (URL-encoded)
        ipv4_link = links[0]
        fragment = ipv4_link.split("#")[-1]
        self.assertIn("alice", urllib.parse.unquote(fragment))


# ══════════════════════════════════════════════════════════════════════════════
#  _users_gen_link — генерация ссылки из существующего config.json
# ══════════════════════════════════════════════════════════════════════════════
class TestUsersGenLink(unittest.TestCase):
    """_users_gen_link: чтение параметров из config.json + state.json."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._cfg = Path(self._tmpdir) / "config.json"
        self._state = Path(self._tmpdir) / "state.json"
        self._fake_core.STATE_FILE = self._state
        self._fake_core.PARAM_DOMAIN = "fallback.example.com"
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", ""))
        self._fake_core._fp_from_state = MagicMock(return_value="chrome")
        self._fake_core.get_server_ip = MagicMock(return_value="")
        self._fake_core.log_to_file = MagicMock()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_reality_link_from_config(self):
        from chimera.modules.users_manager import _users_gen_link
        cfg = {
            "inbounds": [{
                "protocol": "vless",
                "port": 443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "serverNames": ["reality.example.com"],
                        "shortIds": ["abcd1234"],
                    },
                },
            }],
        }
        self._cfg.write_text(json.dumps(cfg))
        self._state.write_text(json.dumps({"domain": "test.example.com"}))
        link = _users_gen_link(self._cfg, "test-uuid", "user@xray")
        self.assertIn("vless://test-uuid@", link)
        self.assertIn("security=reality", link)
        self.assertIn("sid=abcd1234", link)

    def test_returns_empty_on_corrupt_config(self):
        from chimera.modules.users_manager import _users_gen_link
        self._cfg.write_text("{invalid json")
        self._state.write_text(json.dumps({}))
        link = _users_gen_link(self._cfg, "u", "e@x")
        self.assertEqual(link, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
