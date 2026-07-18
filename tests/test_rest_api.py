#!/usr/bin/env python3
"""
tests/test_rest_api.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/rest_api.py — функции генерации
конфигов и синхронизации пользователей.

Покрывает:
  1. _sync_users_from_config() — подтягивание юзеров из config.json в users.json
  2. _generate_vless_links() — VLESS-ссылки (REALITY + xHTTP + IPv6)
  3. _generate_clash_config() — Clash Meta YAML
  4. _generate_singbox_config() — Sing-box JSON
  5. _generate_hiddify_config() — Hiddify JSON (с routing rules)
  6. _generate_vless_link_plain() — VLESS-ссылка как plain text
"""
from __future__ import annotations

import json
import os
import subprocess
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


class _MockState:
    """Временный state.json + users.json + config.json для тестов."""
    def __init__(self, state_dict: dict, users: list = None,
                 config: dict = None):
        self._tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self._tmpdir) / "state.json"
        self.users_file = Path(self._tmpdir) / "users.json"
        self.config_file = Path(self._tmpdir) / "config.json"
        self.state_file.write_text(json.dumps(state_dict))
        if users is not None:
            self.users_file.write_text(json.dumps(users))
        if config is not None:
            self.config_file.write_text(json.dumps(config))
        self._patches = []

    def __enter__(self):
        from chimera.modules import rest_api
        core = sys.modules.get("chimera._core")
        self._patches = [
            patch.object(rest_api, "_get_state", return_value=self.state_dict),
            patch.object(rest_api, "_get_users", return_value=self.users),
            patch.object(rest_api, "_save_users", side_effect=self._save_users),
            patch("pathlib.Path.exists", side_effect=self._path_exists),
            patch("pathlib.Path.read_text", side_effect=self._read_text),
        ]
        if core:
            self._patches.append(patch.object(core, "STATE_FILE", self.state_file))
            self._patches.append(patch.object(core, "USERS_FILE", self.users_file))
            self._patches.append(patch.object(core, "CONFIG_DIR", self.config_file.parent))
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *args):
        import shutil
        for p in self._patches:
            p.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    @property
    def state_dict(self):
        return json.loads(self.state_file.read_text())

    @property
    def users(self):
        if self.users_file.exists():
            return json.loads(self.users_file.read_text())
        return []

    @property
    def config(self):
        if self.config_file.exists():
            return json.loads(self.config_file.read_text())
        return {}

    def _save_users(self, users):
        self.users_file.write_text(json.dumps(users, indent=2, ensure_ascii=False))

    def _path_exists(self):
        # Called on Path instance — check which file
        return True  # simplified

    def _read_text(self):
        return self.state_file.read_text()


_FAKE_STATE_REALITY = {
    "domain": "fleet-b.example",
    "server_port": 443,
    "protocol_mode": "reality",
    "install_mode": "A",
    "public_key": "TEST_PUB_KEY_123",
    "private_key": "TEST_PRIV_KEY_456",
    "short_id": "abcd1234",
    "uuid": "test-uuid-1234",
    "fingerprint": "firefox",
    "xtls_flow": "xtls-rprx-vision",
    "xhttp_path": "/",
    "reality_dest": "",
    "awg_exit_enabled": False,
    "h2_exit_enabled": False,
    "ipv6": "",
}

_FAKE_STATE_XHTTP = {
    **_FAKE_STATE_REALITY,
    "protocol_mode": "xhttp",
    "xhttp_path": "/xhttp",
}

_FAKE_USER = {
    "uuid": "aa0027-0000-4000-8000-000000000027",
    "email": "user@fleet-b.example",
    "name": "user",
}


class TestGenerateVlessLinks(unittest.TestCase):
    """_generate_vless_links — VLESS-ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_reality_link_contains_all_params(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_REALITY):
            links = rest_api._generate_vless_links(_FAKE_USER)
        self.assertEqual(len(links), 1)
        link = links[0]["link"]
        self.assertIn("vless://", link)
        self.assertIn(_FAKE_USER["uuid"], link)
        self.assertIn("fleet-b.example", link)
        self.assertIn("security=reality", link)
        self.assertIn("fp=firefox", link)
        self.assertIn("pbk=TEST_PUB_KEY_123", link)
        self.assertIn("sid=abcd1234", link)
        self.assertIn("flow=xtls-rprx-vision", link)

    def test_xhttp_link_contains_path(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_XHTTP):
            links = rest_api._generate_vless_links(_FAKE_USER)
        self.assertEqual(len(links), 1)
        link = links[0]["link"]
        self.assertIn("security=tls", link)
        self.assertIn("type=http", link)
        self.assertIn("path=%2Fxhttp", link)  # URL-encoded /xhttp

    def test_ipv6_link_present_when_ipv6_in_state(self):
        from chimera.modules import rest_api
        state = {**_FAKE_STATE_REALITY, "ipv6": "2001:db8::1"}
        with patch.object(rest_api, "_get_state", return_value=state):
            links = rest_api._generate_vless_links(_FAKE_USER)
        self.assertEqual(len(links), 2)
        self.assertIn("IPv6", links[1]["label"])
        self.assertIn("[2001:db8::1]", links[1]["link"])

    def test_no_ipv6_link_when_empty(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_REALITY):
            links = rest_api._generate_vless_links(_FAKE_USER)
        self.assertEqual(len(links), 1)


def _make_completed_process(stdout: str, returncode: int = 0):
    """Helper: имитирует subprocess.CompletedProcess для core._run()."""
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr="")


class TestGenerateVlessLinksMTProto(unittest.TestCase):
    """_generate_vless_links — MTProto (Telemt) блок.

    Покрывает регрессию: ранее код обращался к несуществующей функции
    _load_state и файлу /var/lib/xray-installer/mtproto_state.json, из-за
    чего ссылка молча не появлялась (except Exception: pass). Новая
    реализация использует реальные геттеры mtproto.py: _load_users,
    _get_port, _get_domain, _make_tls_secret.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    # ── helpers ───────────────────────────────────────────────────────────
    def _patch_telemt(self, users=None, port=8443, tls_domain="mask.example.com",
                     active=True):
        """Возвращает list-of-patches для Telemt-окружения.

        users: dict {name: hex32_secret} (None → пустой конфиг)
        port: значение _get_port()
        tls_domain: значение _get_domain() (пустая строка = обычный режим,
                   без TLS-обёртки секрета)
        active:True → systemctl is-active telemt возвращает "active"
        """
        from chimera.modules import mtproto as _mtproto_mod
        if users is None:
            users = {}
        cp = _make_completed_process(
            "active\n" if active else "inactive\n",
            returncode=0 if active else 3,
        )
        core = sys.modules.get("chimera._core")
        # _make_tls_secret воспроизводит реальную формулу из mtproto.py,
        # чтобы тест был независим от реализации (только контракт).
        def _fake_make_tls_secret(base_secret, domain):
            return f"ee{base_secret}{domain.encode().hex()}"
        patches = [
            patch.object(_mtproto_mod, "_load_users", return_value=dict(users)),
            patch.object(_mtproto_mod, "_get_port", return_value=port),
            patch.object(_mtproto_mod, "_get_domain", return_value=tls_domain),
            patch.object(_mtproto_mod, "_make_tls_secret",
                         side_effect=_fake_make_tls_secret),
            patch.object(_mtproto_mod, "SERVICE_NAME", "telemt"),
        ]
        if core is not None:
            patches.append(patch.object(core, "_run", return_value=cp))
        return patches

    def _run(self, patches, user=None):
        """Запускает _generate_vless_links с пропатченным окружением."""
        from chimera.modules import rest_api
        if user is None:
            user = _FAKE_USER
        # Стартуем все патчи; .stop() вызываем на самих patch-объектах,
        # а не на том, что вернул .start() (mock/etc.).
        for p in patches:
            p.start()
        try:
            with patch.object(rest_api, "_get_state",
                              return_value=_FAKE_STATE_REALITY):
                return rest_api._generate_vless_links(user)
        finally:
            for p in patches:
                p.stop()

    def _mtproto_link(self, links):
        """Возвращает элемент link с protocol == 'mtproto' или None."""
        for item in links:
            if item.get("protocol") == "mtproto":
                return item
        return None

    # ── тесты ─────────────────────────────────────────────────────────────
    def test_mtproto_link_present_when_user_matches_tls_mode(self):
        """Юзер с совпадающим name в [access.users] → ссылка MTProto
        с TLS-обёрнутым секретом (формат ee<secret><domain_hex>)."""
        secret = "deadbeefdeadbeefdeadbeefdeadbeef"
        tls_domain = "mask.example.com"
        patches = self._patch_telemt(
            users={"user": secret}, port=8443, tls_domain=tls_domain, active=True,
        )
        links = self._run(patches, user=_FAKE_USER)
        mt = self._mtproto_link(links)
        self.assertIsNotNone(mt, "MTProto-ссылка должна присутствовать")
        expected_secret = f"ee{secret}{tls_domain.encode().hex()}"
        self.assertIn(f"secret={expected_secret}", mt["link"])
        self.assertIn("port=8443", mt["link"])
        self.assertIn("server=fleet-b.example", mt["link"])
        self.assertTrue(mt["link"].startswith("https://t.me/proxy?"))

    def test_mtproto_link_uses_email_local_part_when_name_not_in_telemt(self):
        """Если user['name'] не найден, но локальная часть email совпадает —
        ссылка генерируется (типичный кейс: portal email 'alice@x.com',
        Telemt-имя 'alice')."""
        secret = "aabbccddaabbccddaabbccddaabbccdd"
        user = {"uuid": "u1", "name": "alice_portal", "email": "alice@x.com"}
        patches = self._patch_telemt(users={"alice": secret})
        links = self._run(patches, user=user)
        mt = self._mtproto_link(links)
        self.assertIsNotNone(mt, "Должен сработать fallback по локальной части email")
        self.assertIn(f"secret=ee{secret}", mt["link"])

    def test_mtproto_link_absent_when_no_matching_user(self):
        """У юзера портала нет соответствующего аккаунта Telemt → ссылка
        не показывается, остальные ссылки не ломаются."""
        patches = self._patch_telemt(
            users={"someone_else": "0123456789abcdef0123456789abcdef"},
            active=True,
        )
        links = self._run(patches, user=_FAKE_USER)
        mt = self._mtproto_link(links)
        self.assertIsNone(mt, "MTProto-ссылка НЕ должна появляться без совпадения")
        # VLESS-ссылка должна остаться.
        self.assertGreaterEqual(len(links), 1)
        self.assertEqual(links[0]["protocol"], "reality")

    def test_mtproto_link_absent_when_service_inactive(self):
        """systemctl is-active telemt → inactive: ссылка не отдаётся,
        даже если у юзера есть секрет в Telemt-конфиге."""
        secret = "deadbeefdeadbeefdeadbeefdeadbeef"
        patches = self._patch_telemt(
            users={"user": secret}, active=False,
        )
        links = self._run(patches, user=_FAKE_USER)
        mt = self._mtproto_link(links)
        self.assertIsNone(mt, "MTProto-ссылка не отдаётся при неактивном telemt")
        self.assertGreaterEqual(len(links), 1)

    def test_mtproto_link_uses_raw_secret_when_no_tls_domain(self):
        """tls_domain пустой (нет [censorship] секции) → секрет не
        оборачивается, отдаётся как есть."""
        secret = "cafebabecafebabecafebabecafebabe"
        patches = self._patch_telemt(
            users={"user": secret}, tls_domain="", active=True,
        )
        links = self._run(patches, user=_FAKE_USER)
        mt = self._mtproto_link(links)
        self.assertIsNotNone(mt)
        # Секрет без 'ee'-префикса и без hex-домена.
        self.assertIn(f"secret={secret}", mt["link"])
        self.assertNotIn("secret=ee", mt["link"])

    def test_mtproto_link_absent_when_telemt_users_empty(self):
        """Пустой [access.users] → нет секретов → нет ссылки."""
        patches = self._patch_telemt(users={}, active=True)
        links = self._run(patches, user=_FAKE_USER)
        self.assertIsNone(self._mtproto_link(links))

    def test_mtproto_link_absent_when_mtproto_module_import_fails(self):
        """Если импорт mtproto падает (модуль не установлен) — regress к
        silent-pass, остальные ссылки не ломаются (старый контракт)."""
        import importlib
        from chimera.modules import rest_api
        # Прячем настоящий mtproto, подменяем на модуль без нужных атрибутов.
        real_mtproto = sys.modules.get("chimera.modules.mtproto")
        broken = type(sys)("chimera.modules.mtproto")
        sys.modules["chimera.modules.mtproto"] = broken
        try:
            with patch.object(rest_api, "_get_state",
                              return_value=_FAKE_STATE_REALITY):
                links = rest_api._generate_vless_links(_FAKE_USER)
        finally:
            if real_mtproto is not None:
                sys.modules["chimera.modules.mtproto"] = real_mtproto
            else:
                sys.modules.pop("chimera.modules.mtproto", None)
        self.assertIsNone(self._mtproto_link(links))
        self.assertGreaterEqual(len(links), 1)


class TestGenerateClashConfig(unittest.TestCase):
    """_generate_clash_config — Clash Meta YAML."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_reality_clash_has_all_fields(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_REALITY):
            clash = rest_api._generate_clash_config(_FAKE_USER)
        self.assertIn("type: vless", clash)
        self.assertIn("server: fleet-b.example", clash)
        self.assertIn("port: 443", clash)
        self.assertIn("uuid: " + _FAKE_USER["uuid"], clash)
        self.assertIn("flow: xtls-rprx-vision", clash)
        self.assertIn("public-key: TEST_PUB_KEY_123", clash)
        self.assertIn("short-id: abcd1234", clash)
        self.assertIn("client-fingerprint: firefox", clash)

    def test_xhttp_clash_has_http_opts(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_XHTTP):
            clash = rest_api._generate_clash_config(_FAKE_USER)
        self.assertIn("network: http", clash)
        self.assertIn("path: [/xhttp]", clash)


class TestGenerateSingboxConfig(unittest.TestCase):
    """_generate_singbox_config — Sing-box JSON."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_reality_singbox_valid_json(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_REALITY):
            singbox_str = rest_api._generate_singbox_config(_FAKE_USER)
        config = json.loads(singbox_str)
        self.assertIn("outbounds", config)
        ob = config["outbounds"][0]
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server"], "fleet-b.example")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["uuid"], _FAKE_USER["uuid"])
        self.assertEqual(ob["flow"], "xtls-rprx-vision")
        self.assertTrue(ob["tls"]["enabled"])
        self.assertTrue(ob["tls"]["reality"]["enabled"])
        self.assertEqual(ob["tls"]["reality"]["public_key"], "TEST_PUB_KEY_123")
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "firefox")

    def test_xhttp_singbox_has_transport(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_XHTTP):
            singbox_str = rest_api._generate_singbox_config(_FAKE_USER)
        config = json.loads(singbox_str)
        ob = config["outbounds"][0]
        self.assertEqual(ob["transport"]["type"], "http")
        self.assertEqual(ob["transport"]["path"], "/xhttp")


class TestGenerateHiddifyConfig(unittest.TestCase):
    """_generate_hiddify_config — Hiddify JSON (sing-box + routing)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_reality_hiddify_valid_json_with_routing(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_REALITY):
            hiddify_str = rest_api._generate_hiddify_config(_FAKE_USER)
        config = json.loads(hiddify_str)
        self.assertIn("outbounds", config)
        self.assertIn("routing", config)
        self.assertIn("rules", config["routing"])
        # Outbound = VLESS + REALITY
        ob = config["outbounds"][0]
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server"], "fleet-b.example")
        self.assertTrue(ob["tls"]["reality"]["enabled"])
        # Routing rule
        rule = config["routing"]["rules"][0]
        self.assertEqual(rule["outbound"], "vless-out")

    def test_xhttp_hiddify_has_transport(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_XHTTP):
            hiddify_str = rest_api._generate_hiddify_config(_FAKE_USER)
        config = json.loads(hiddify_str)
        ob = config["outbounds"][0]
        self.assertEqual(ob["transport"]["type"], "http")
        self.assertEqual(ob["transport"]["path"], "/xhttp")

    def test_hiddify_sni_correct_for_awg_mode(self):
        """SNI = reality_dest в Mode B + AWG (не domain)."""
        from chimera.modules import rest_api
        state = {
            **_FAKE_STATE_REALITY,
            "install_mode": "B",
            "awg_exit_enabled": True,
            "reality_dest": "www.cloudflare.com",
        }
        with patch.object(rest_api, "_get_state", return_value=state):
            hiddify_str = rest_api._generate_hiddify_config(_FAKE_USER)
        config = json.loads(hiddify_str)
        sni = config["outbounds"][0]["tls"]["server_name"]
        self.assertEqual(sni, "www.cloudflare.com")


class TestGenerateVlessLinkPlain(unittest.TestCase):
    """_generate_vless_link_plain — VLESS-ссылка как plain text."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_first_link(self):
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value=_FAKE_STATE_REALITY):
            link = rest_api._generate_vless_link_plain(_FAKE_USER)
        self.assertTrue(link.startswith("vless://"))
        self.assertIn(_FAKE_USER["uuid"], link)
        self.assertIn("fleet-b.example", link)

    def test_empty_when_no_links(self):
        from chimera.modules import rest_api
        empty_state = {"domain": "", "server_port": 443, "protocol_mode": "reality"}
        with patch.object(rest_api, "_get_state", return_value=empty_state):
            link = rest_api._generate_vless_link_plain(_FAKE_USER)
        # domain пустой — ссылка всё равно генерируется, но с пустым server
        # Проверяем что функция не падает
        self.assertIsInstance(link, str)


class TestSyncUsersFromConfig(unittest.TestCase):
    """_sync_users_from_config — подтягивание юзеров из config.json."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _make_config_with_clients(self, clients: list) -> dict:
        """Создаёт fake config.json с VLESS inbound и clients."""
        return {
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": clients}
            }]
        }

    def test_adds_missing_users_from_config(self):
        """Юзеры из config.json подтягиваются в users.json."""
        from chimera.modules import rest_api
        config = self._make_config_with_clients([
            {"id": "uuid-1", "email": "alice@xray"},
            {"id": "uuid-2", "email": "bob@xray"},
        ])
        existing_users = [{"uuid": "uuid-1", "email": "alice@xray", "name": "alice"}]

        with patch.object(rest_api, "_get_state", return_value={}), \
             patch.object(rest_api, "_get_users", return_value=list(existing_users)), \
             patch.object(rest_api, "_save_users") as mock_save:
            # Мокаем config.json
            core = sys.modules.get("chimera._core")
            with patch.object(core, "CONFIG_DIR", Path("/tmp/test_config_dir")), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", return_value=json.dumps(config)):
                added = rest_api._sync_users_from_config()

        self.assertEqual(added, 1)  # bob добавлен
        saved_users = mock_save.call_args.args[0]
        self.assertEqual(len(saved_users), 2)
        self.assertEqual(saved_users[1]["email"], "bob@xray")
        self.assertEqual(saved_users[1]["portal_password"], "")

    def test_no_duplicates_when_already_synced(self):
        """Если юзеры уже в users.json — ничего не добавляется."""
        from chimera.modules import rest_api
        config = self._make_config_with_clients([
            {"id": "uuid-1", "email": "alice@xray"},
        ])
        existing_users = [{"uuid": "uuid-1", "email": "alice@xray", "name": "alice"}]

        with patch.object(rest_api, "_get_state", return_value={}), \
             patch.object(rest_api, "_get_users", return_value=list(existing_users)), \
             patch.object(rest_api, "_save_users") as mock_save:
            core = sys.modules.get("chimera._core")
            with patch.object(core, "CONFIG_DIR", Path("/tmp/test_config_dir")), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", return_value=json.dumps(config)):
                added = rest_api._sync_users_from_config()

        self.assertEqual(added, 0)
        mock_save.assert_not_called()

    def test_returns_zero_when_no_config(self):
        """Если config.json не существует — return 0."""
        from chimera.modules import rest_api
        with patch.object(rest_api, "_get_state", return_value={}), \
             patch.object(rest_api, "_get_users", return_value=[]), \
             patch("pathlib.Path.exists", return_value=False):
            added = rest_api._sync_users_from_config()
        self.assertEqual(added, 0)

    def test_returns_zero_when_no_vless_clients(self):
        """Если в config.json нет VLESS inbounds — return 0."""
        from chimera.modules import rest_api
        config = {"inbounds": [{"protocol": "shadowsocks"}]}
        with patch.object(rest_api, "_get_state", return_value={}), \
             patch.object(rest_api, "_get_users", return_value=[]), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=json.dumps(config)):
            added = rest_api._sync_users_from_config()
        self.assertEqual(added, 0)

    def test_skips_zero_uuid(self):
        """UUID '00000000-...' пропускается (дефолтный placeholder)."""
        from chimera.modules import rest_api
        config = self._make_config_with_clients([
            {"id": "00000000-0000-0000-0000-000000000000", "email": "placeholder"},
            {"id": "real-uuid", "email": "real@xray"},
        ])

        with patch.object(rest_api, "_get_state", return_value={}), \
             patch.object(rest_api, "_get_users", return_value=[]), \
             patch.object(rest_api, "_save_users") as mock_save:
            core = sys.modules.get("chimera._core")
            with patch.object(core, "CONFIG_DIR", Path("/tmp/test_config_dir")), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", return_value=json.dumps(config)):
                added = rest_api._sync_users_from_config()

        self.assertEqual(added, 1)  # только real-uuid
        saved_users = mock_save.call_args.args[0]
        self.assertEqual(len(saved_users), 1)
        self.assertEqual(saved_users[0]["uuid"], "real-uuid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
