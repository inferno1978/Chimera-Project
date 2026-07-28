#!/usr/bin/env python3
"""
tests/test_ios_patch4_open_surfaces.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты для патча №4 — открытие двух закрытых TODO-веток
(generate_client_links_ios и client_config_export vless-link-ios.txt)
с тем же shadow-паттерном, что подтверждён в do_user_show_link_ios.

Покрытие (по спецификации задачи):
  1. generate_client_links_ios(): сгенерированная ссылка не содержит
     "flow=", содержит shadow UUID (не PARAM_UUID оригинала).
  2. client_config_export: vless-link-ios.txt для REALITY не содержит
     "flow=", для xHTTP идентичен обычному vless-link.txt.
  3. do_user_list() / _users_counts: shadow-клиенты не задваивают
     счётчик реальных пользователей — golden-тест на количестве
     clients[] с и без shadow-записей.
  4. Полный прогон существующих тестов на do_user_add/delete/
     show_link_ios — не регрессируют (отдельный прогон pytest).

Дополнительно:
  • _unified_load_users помечает shadow полем is_ios_shadow=True.
  • status_panel._users_counts фильтрует shadow из total/active.
  • do_user_list рендерит shadow отдельным блоком (без номера).
  • generate_client_links_ios и _core.py пункт K — раскомментированы.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import types
import unittest
import uuid as _uuid_mod
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _make_reality_config(initial_clients=None, sni="sni.example.com"):
    tmpdir = Path(tempfile.mkdtemp())
    cfg_path = tmpdir / "config.json"
    if initial_clients is None:
        initial_clients = [{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "alice@example.com",
            "flow": "xtls-rprx-vision",
        }]
    config = {
        "inbounds": [{
            "protocol": "vless",
            "port": 443,
            "settings": {"clients": list(initial_clients)},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [sni],
                    "publicKey": "TEST_PUB_KEY",
                    "shortIds": ["abcd1234"],
                },
            },
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    cfg_path.write_text(json.dumps(config, indent=2))
    return tmpdir, cfg_path


def _mock_core_for_users_manager(fake_core, cfg_path=None, state_dict=None):
    fake_core.gen_uuid = lambda: str(_uuid_mod.uuid4())
    fake_core.get_server_country_cached = MagicMock(return_value=("RU", "Russia", ""))
    fake_core.PARAM_DOMAIN = "example.com"
    fake_core._fp_from_state = MagicMock(return_value="chrome")
    fake_core.STATE_FILE = Path("/nonexistent-state.json")
    fake_core.log_to_file = MagicMock()
    fake_core.warn = MagicMock()
    fake_core.info = MagicMock()
    fake_core._xray_safe_apply_config = MagicMock()
    fake_core._nginx_restart_if_reality = MagicMock()
    fake_core._run = MagicMock()
    fake_core._box_link = MagicMock()
    fake_core._box_top = MagicMock()
    fake_core._box_row = MagicMock()
    fake_core._box_bottom = MagicMock()
    fake_core._box_sep = MagicMock()
    fake_core._box_ok = MagicMock()
    fake_core._box_warn = MagicMock()
    fake_core._box_wrap_msg = MagicMock()
    fake_core._get_box_width = MagicMock(return_value=80)
    fake_core.get_server_ip = MagicMock(return_value="1.2.3.4")
    fake_core.CYAN = ""
    fake_core.BOLD = ""
    fake_core.NC = ""
    fake_core.DIM = ""
    fake_core.BLUE = ""
    fake_core.GREEN = ""
    fake_core.MAGENTA = ""
    # PARAM_* — нужны для generate_client_links_ios
    fake_core.PARAM_UUID = "00000000-0000-0000-0000-000000000001"
    fake_core.PARAM_FINGERPRINT = "chrome"
    fake_core.PROTOCOL_MODE = "reality"
    fake_core.PARAM_REALITY_DEST = ""
    fake_core.AWG_EXIT_ENABLED = False
    fake_core.PARAM_DOMAIN = "example.com"
    fake_core.PARAM_PUBLIC_KEY = "TEST_PUB_KEY"
    fake_core.PARAM_SHORTID = "abcd1234"
    fake_core.XHTTP_PATH = "/"
    fake_core.XHTTP_MODE = "stream-up"
    fake_core.SERVER_PORT = 443
    fake_core.IS_IPV6_AVAILABLE = False
    return fake_core


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 1: generate_client_links_ios — нет flow=, UUID shadow (не оригинал)
# ══════════════════════════════════════════════════════════════════════════════
class TestGenerateClientLinksIosUsesShadow(unittest.TestCase):
    """generate_client_links_ios() для REALITY: каждая сгенерированная
    ссылка не содержит "flow=" и использует shadow UUID, а не PARAM_UUID."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_reality_config()
        _mock_core_for_users_manager(self._fake_core)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_links_no_flow_and_use_shadow_uuid(self):
        from chimera.modules import users_manager

        captured_links = []
        self._fake_core._box_link = lambda link: captured_links.append(link)

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None), \
             patch.object(Path, "write_text", lambda self, data, *a, **kw: len(data)), \
             patch.object(Path, "chmod", lambda self, *a, **kw: None):
            users_manager.generate_client_links_ios()

        self.assertGreater(len(captured_links), 0,
                           "Должна быть хотя бы одна ссылка (IPv4/Domain)")
        orig_uuid = "00000000-0000-0000-0000-000000000001"

        # После вызова в clients[] должен появиться shadow.
        c = json.loads(self._cfg_path.read_text())
        clients = c["inbounds"][0]["settings"]["clients"]
        shadows = [cl for cl in clients if cl.get("email", "").endswith("__ios")]
        self.assertEqual(len(shadows), 1, "Должен быть 1 shadow-клиент")
        shadow_uuid = shadows[0]["id"]

        for link in captured_links:
            self.assertNotIn("flow=", link,
                             f"iOS-ссылка не должна содержать flow=: {link}")
            self.assertNotIn("xtls-rprx-vision", link)
            self.assertIn(shadow_uuid, link,
                          f"Ссылка должна использовать shadow UUID, not orig: {link}")
            self.assertNotIn(orig_uuid, link,
                             f"Ссылка не должна содержать оригинальный UUID: {link}")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 2: client_config_export — vless-link-ios.txt
# ══════════════════════════════════════════════════════════════════════════════
class TestClientConfigExportIosLink(unittest.TestCase):
    """vless-link-ios.txt для REALITY не содержит flow=, использует shadow UUID.
    Для xHTTP — идентичен обычному vless-link.txt (shadow не нужен)."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core_for_users_manager(self._fake_core)
        self._fake_core.STATE_FILE = MagicMock()
        self._fake_core.STATE_FILE.exists = MagicMock(return_value=True)

    def test_reality_ios_link_no_flow_uses_shadow_uuid(self):
        """Для REALITY: vless-link-ios.txt не содержит flow=, UUID = shadow."""
        from chimera.modules import client_config_export

        tmpdir = Path(tempfile.mkdtemp())
        cfg_path = tmpdir / "config.json"
        cfg_path.write_text(json.dumps({
            "inbounds": [{
                "protocol": "vless",
                "port": 443,
                "settings": {"clients": [{
                    "id": "11111111-0000-0000-0000-000000000001",
                    "email": "alice@example.com",
                    "flow": "xtls-rprx-vision",
                }]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverNames": ["sni.example.com"],
                        "publicKey": "TEST_PUB_KEY",
                        "shortIds": ["abcd1234"],
                    },
                },
            }],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }))

        state = {
            "domain": "vpn.example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "install_mode": "A",
            "public_key": "TEST_PUB_KEY",
            "short_id": "abcd1234",
            "uuid": "11111111-0000-0000-0000-000000000001",
            "fingerprint": "chrome",
            "xtls_flow": "xtls-rprx-vision",
            "xhttp_path": "/",
            "reality_dest": "",
            "awg_exit_enabled": False,
        }
        state_file = tmpdir / "state.json"
        state_file.write_text(json.dumps(state))

        out_dir = tmpdir / "configs"
        written = {}

        def _capture_write(self_path, data, *a, **kw):
            s = str(self_path)
            if "configs" in s:
                name = Path(s).name
                _dest = out_dir / name
                os.makedirs(str(_dest.parent), exist_ok=True) if False else None
                # Не пишем реально — сохраняем в dict.
                written[name] = data
                return len(data)
            return _orig_write(self_path, data, *a, **kw)

        _orig_write = Path.write_text

        with patch.object(self._fake_core, "STATE_FILE", state_file), \
             patch.object(client_config_export, "_core_module", return_value=self._fake_core), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None), \
             patch("chimera.modules.users_manager._users_get_config", return_value=cfg_path), \
             patch("chimera.modules.users_manager._core_module", return_value=self._fake_core), \
             patch("chimera.modules.users_manager._users_apply_config", lambda cfg: None):
            client_config_export.do_generate_client_config()

        # vless-link.txt — обычная REALITY-ссылка (с flow=).
        vless_link = written.get("vless-link.txt", "")
        self.assertIn("flow=xtls-rprx-vision", vless_link)
        self.assertIn("11111111-0000-0000-0000-000000000001", vless_link)

        # vless-link-ios.txt — без flow=, с shadow UUID.
        ios_link = written.get("vless-link-ios.txt", "")
        self.assertTrue(ios_link, "vless-link-ios.txt должен быть создан")
        self.assertNotIn("flow=", ios_link)
        self.assertNotIn("xtls-rprx-vision", ios_link)
        # UUID должен быть другим (shadow), не оригинальный.
        self.assertNotIn("11111111-0000-0000-0000-000000000001", ios_link)
        # И shadow должен теперь быть в clients[].
        c = json.loads(cfg_path.read_text())
        clients = c["inbounds"][0]["settings"]["clients"]
        shadows = [cl for cl in clients if cl.get("email", "").endswith("__ios")]
        self.assertEqual(len(shadows), 1)
        self.assertIn(shadows[0]["id"], ios_link)

        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_xhttp_ios_link_identical_to_plain(self):
        """Для xHTTP: vless-link-ios.txt идентичен vless-link.txt (shadow не нужен)."""
        from chimera.modules import client_config_export
        import os

        tmpdir = Path(tempfile.mkdtemp())
        cfg_path = tmpdir / "config.json"
        cfg_path.write_text(json.dumps({
            "inbounds": [{
                "protocol": "vless",
                "port": 8443,
                "settings": {"clients": [{
                    "id": "22222222-0000-0000-0000-000000000002",
                    "email": "bob@example.com",
                }]},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {"path": "/xhttp", "mode": "stream-up"},
                },
            }],
        }))

        state = {
            "domain": "vpn.example.com",
            "server_port": 8443,
            "protocol_mode": "xhttp",
            "install_mode": "A",
            "uuid": "22222222-0000-0000-0000-000000000002",
            "fingerprint": "chrome",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "reality_dest": "",
            "awg_exit_enabled": False,
        }
        state_file = tmpdir / "state.json"
        state_file.write_text(json.dumps(state))

        out_dir = tmpdir / "configs"
        written = {}
        _orig_write = Path.write_text

        def _capture_write(self_path, data, *a, **kw):
            s = str(self_path)
            if "configs" in s:
                name = Path(s).name
                written[name] = data
                return len(data)
            return _orig_write(self_path, data, *a, **kw)

        with patch.object(self._fake_core, "STATE_FILE", state_file), \
             patch.object(client_config_export, "_core_module", return_value=self._fake_core), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None):
            client_config_export.do_generate_client_config()

        vless_link = written.get("vless-link.txt", "").strip()
        ios_link = written.get("vless-link-ios.txt", "").strip()

        self.assertTrue(vless_link)
        self.assertTrue(ios_link)
        # Для xHTTP postprocessor — no-op, ссылки должны совпадать.
        self.assertEqual(vless_link, ios_link)
        # Ни в одной нет flow (xHTTP не использует flow).
        self.assertNotIn("flow=", vless_link)
        self.assertNotIn("flow=", ios_link)

        # clients[] не должен увеличиться (shadow не создавался).
        c = json.loads(cfg_path.read_text())
        clients = c["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(clients), 1, "xHTTP не должен создавать shadow")

        shutil.rmtree(tmpdir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 3: счётчики не задваиваются от shadow
# ══════════════════════════════════════════════════════════════════════════════
class TestShadowDoesNotDoubleCount(unittest.TestCase):
    """Shadow-клиенты не должны задваивать счётчик реальных пользователей.
    _users_counts фильтрует по is_ios_shadow, _unified_load_users помечает."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core_for_users_manager(self._fake_core)

    def _make_cfg_with_shadow(self, real_count=2, with_shadow=True):
        """Создаёт cfg с real_count реальными клиентами + опционально shadow."""
        clients = []
        for i in range(real_count):
            clients.append({
                "id": f"aaa{i:08x}-0000-0000-0000-0000000000{i:02d}",
                "email": f"user{i}@example.com",
                "flow": "xtls-rprx-vision",
            })
        if with_shadow:
            clients.append({
                "id": "bbbbbbbb-0000-0000-0000-000000000099",
                "email": "user0@example.com__ios",
                # без flow
            })
        return _make_reality_config(clients)

    def test_unified_load_users_marks_shadow(self):
        """_unified_load_users помечает shadow через is_ios_shadow=True.

        Используем временную директорию и monkey-patch Path в
        users_manager namespace, чтобы указать на наш тестовый config.json."""
        from chimera.modules import users_manager

        tmpdir, cfg_path = self._make_cfg_with_shadow(real_count=2, with_shadow=True)
        cfg_text = cfg_path.read_text()
        try:
            # Подменяем Path в users_manager — _unified_load_users читает
            # Path("/etc/xray/config.json") напрямую. Сделаем простой wrapper.
            real_path = Path

            class _P(type(real_path)):
                pass

            # Сохраняем оригинал и подменяем конструктор.
            orig_path_in_module = users_manager.Path
            try:
                class _FakePath(real_path):
                    def __new__(cls, *args, **kwargs):
                        # Если путь — наш тестовый, возвращаем объект с
                        # предсказуемым поведением. Иначе — реальный Path.
                        if args and args[0] in (
                            "/etc/xray/config.json",
                            "/usr/local/etc/xray/config.json",
                        ):
                            obj = object.__new__(cls)
                            return obj
                        return real_path(*args, **kwargs)

                    def __init__(self, *args, **kwargs):
                        if args and args[0] in (
                            "/etc/xray/config.json",
                            "/usr/local/etc/xray/config.json",
                        ):
                            self._fake = True
                            self._str = args[0]
                        else:
                            self._fake = False
                            super().__init__(*args, **kwargs)

                    def exists(self, *a, **kw):
                        if getattr(self, "_fake", False):
                            return self._str == "/etc/xray/config.json"
                        return real_path(self).exists(*a, **kw)

                    def read_text(self, *a, **kw):
                        if getattr(self, "_fake", False):
                            return cfg_text
                        return real_path(str(self)).read_text(*a, **kw)

                users_manager.Path = _FakePath
                users = users_manager._unified_load_users()
            finally:
                users_manager.Path = orig_path_in_module

            shadows = [u for u in users if u.get("is_ios_shadow")]
            real = [u for u in users if not u.get("is_ios_shadow")]
            self.assertEqual(len(shadows), 1, f"Должен быть 1 shadow, got {len(shadows)}")
            self.assertEqual(len(real), 2, f"Должно быть 2 реальных, got {len(real)}")
            self.assertTrue(shadows[0]["email"].endswith("__ios"))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_users_counts_excludes_shadow(self):
        """status_panel._users_counts должен исключать shadow из total/active.

        Патчим _core_module() в status_panel, чтобы вернуть fake_core
        с предзаполненным _unified_load_users."""
        from chimera.modules import status_panel

        fake_users = [
            {"uuid": "u1", "email": "user0@example.com", "name": "u0", "source": "A"},
            {"uuid": "u2", "email": "user1@example.com", "name": "u1", "source": "A"},
            {"uuid": "shadow", "email": "user0@example.com__ios",
             "name": "user0", "source": "A", "is_ios_shadow": True},
        ]
        fake_core = MagicMock()
        fake_core._unified_load_users = MagicMock(return_value=fake_users)
        with patch.object(status_panel, "_core_module", return_value=fake_core):
            active, total = status_panel._users_counts()

        # 2 реальных (оба active) — shadow не считается.
        self.assertEqual(total, 2,
                         f"total должен быть 2 (без shadow), got {total}")
        self.assertEqual(active, 2,
                         f"active должен быть 2 (без shadow), got {active}")

    def test_users_counts_without_shadow_unchanged(self):
        """Без shadow — поведение идентичное допатчевому (golden)."""
        from chimera.modules import status_panel

        fake_users = [
            {"uuid": "u1", "email": "a@x.com", "name": "a", "source": "A"},
            {"uuid": "u2", "email": "b@x.com", "name": "b", "source": "A",
             "disabled": True},
        ]
        fake_core = MagicMock()
        fake_core._unified_load_users = MagicMock(return_value=fake_users)
        with patch.object(status_panel, "_core_module", return_value=fake_core):
            active, total = status_panel._users_counts()
        self.assertEqual(total, 2)
        self.assertEqual(active, 1)  # один disabled


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 4: пункт K в _menu_users раскомментирован
# ══════════════════════════════════════════════════════════════════════════════
class TestMenuUsersKItemUncommented(unittest.TestCase):
    """Подменю 'Управление пользователями' (_menu_users в _core.py) —
    пункт K должен быть активен и вызывать generate_client_links_ios.

    Реальный путь пользователя:
      main_menu → пункт "2" → _menu_users() → пункт "K" → generate_client_links_ios()

    Это protects от случайного возврата к закомментированному состоянию
    (патч №2 закомментировал, патч №4 раскомментировал)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _extract_menu_users_block(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        m = re.search(r'def _menu_users\(\).*?(?=\ndef [a-z_])',
                      src, re.DOTALL)
        self.assertIsNotNone(m, "_menu_users не найдена в _core.py")
        return m.group(0)

    def test_k_item_active_in_menu_users(self):
        block = self._extract_menu_users_block()
        found = False
        for line in block.split("\n"):
            stripped = line.strip()
            if stripped.startswith('_box_item("K"'):
                found = True
                break
        self.assertTrue(found,
                        "Пункт K должен быть активен в _menu_users после патча №4")

    def test_k_handler_calls_generate_client_links_ios(self):
        block = self._extract_menu_users_block()
        self.assertIn("generate_client_links_ios()", block,
                      "Обработчик ch == 'k' в _menu_users должен вызывать "
                      "generate_client_links_ios()")

    def test_no_todo_broken_in_menu_users(self):
        """В _menu_users не должно остаться TODO 'broken until shadow-client fix'."""
        block = self._extract_menu_users_block()
        self.assertNotIn(
            "broken until shadow-client fix",
            block,
            "TODO 'broken until shadow-client fix' должен быть снят "
            "патчем №4 в _menu_users"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 5: do_user_list рендерит shadow отдельно
# ══════════════════════════════════════════════════════════════════════════════
class TestDoUserListRendersShadowSeparately(unittest.TestCase):
    """do_user_list показывает shadow-клиентов отдельным блоком без номера."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core_for_users_manager(self._fake_core)

    def test_shadow_in_separate_block(self):
        from chimera.modules import users_manager

        tmpdir, cfg_path = _make_reality_config([
            {"id": "aaaaaaaa-0000-0000-0000-000000000001",
             "email": "alice@example.com", "flow": "xtls-rprx-vision"},
            {"id": "bbbbbbbb-0000-0000-0000-000000000002",
             "email": "alice@example.com__ios"},
        ])
        try:
            output = []
            with patch.object(users_manager, "_users_get_config", return_value=cfg_path), \
                 patch.object(users_manager, "_core_module", return_value=self._fake_core), \
                 patch("builtins.print", lambda *a, **kw: output.append(" ".join(str(x) for x in a))):
                users_manager.do_user_list()

            joined = "\n".join(output)
            # Shadow-блок должен быть помечен явно.
            self.assertIn("iOS-shadow", joined)
            self.assertIn("__ios", joined)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 6: пункт K в do_unified_user_manager остался активным (не сломан)
# ══════════════════════════════════════════════════════════════════════════════
class TestUnifiedManagerKItemStillActive(unittest.TestCase):
    """Пункт K в do_unified_user_manager (патч №3) должен остаться активным
    и не быть затронут патчем №4."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_k_item_in_unified_manager(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        m = re.search(r'def do_unified_user_manager\(\).*?(?=\ndef [a-z_])',
                      src, re.DOTALL)
        self.assertIsNotNone(m, "do_unified_user_manager не найдена")
        block = m.group(0)
        self.assertIn('_box_item("K"', block,
                       "Пункт K должен быть в do_unified_user_manager (патч №3)")
        self.assertIn("do_user_show_link_ios_by_uuid", block)


if __name__ == "__main__":
    unittest.main(verbosity=2)
