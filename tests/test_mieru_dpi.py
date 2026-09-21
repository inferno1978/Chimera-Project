#!/usr/bin/env python3
"""
tests/test_mieru_dpi.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mieru_dpi.py — модуля «Mieru + B4»
(DPI bypass через Mieru-транспорт, паритет Xray-связке).

Покрывает:
  1. State: load/save/defaults, включение/выключение режима
  2. is_mieru_dpi_active: enabled + installed, отказ при сносе mieru
  3. _normalize_domain: wildcard → apex, мусор → None
  4. collect_b4_domains: enabled-сеты b4 → домены (lazy dpi_bypass)
  5. sync_b4_to_mieru: идемпотентность, метки changed
  6. build_mieru_route_rules: формат sing-box route.rules
  7. build_karing_split_config: split-конфиг (домены → mieru, final=direct)
  8. _e2e_probe: генерация клиентского конфига (изоляция HOME,
     trafficPattern JSON-формой), недоступность = graceful skip
  9. Интеграция подписки (мульти-нодовая): mieru-outbound в selector +
     Streaming, route-правила ВЫШЕ geosite, protect домена mita
 10. Интеграция подписки (одиночная): route.rules → mieru-outbound
 11. Маркеры меню: пункт [MB] в _core.py рядом с [B]
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules.setdefault("chimera", types.ModuleType("chimera"))
    sys.modules.setdefault("chimera.modules", types.ModuleType("chimera.modules"))
    sys.modules["chimera._core"] = fake_core
    return fake_core


_setup_core_in_sysmodules()

from chimera.modules import mieru_dpi  # noqa: E402


def _tmp_state_paths(testcase, tmpdir):
    """Подменяет пути state-файлов mieru_dpi на временные."""
    testcase._old_state = mieru_dpi._STATE_FILE
    testcase._old_mieru_state = mieru_dpi._MIERU_STATE
    mieru_dpi._STATE_FILE = Path(tmpdir) / "mieru_dpi.json"
    mieru_dpi._MIERU_STATE = Path(tmpdir) / "mieru.json"


class TestState(unittest.TestCase):
    """State: defaults, вкл/выкл, идемпотентность сохранения."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        _tmp_state_paths(self, self._td.name)

    def tearDown(self):
        mieru_dpi._STATE_FILE = self._old_state
        mieru_dpi._MIERU_STATE = self._old_mieru_state
        self._td.cleanup()

    def test_defaults_when_no_file(self):
        st = mieru_dpi._load_state()
        self.assertFalse(st.get("enabled"))
        self.assertEqual(st.get("route_domains"), [])
        self.assertEqual(st.get("synced_sets"), [])

    def test_save_load_roundtrip(self):
        st = mieru_dpi._load_state()
        st["enabled"] = True
        st["route_domains"] = ["youtube.com", "googlevideo.com"]
        mieru_dpi._save_state(st)
        st2 = mieru_dpi._load_state()
        self.assertTrue(st2.get("enabled"))
        self.assertEqual(st2["route_domains"], ["youtube.com", "googlevideo.com"])

    def test_is_active_requires_enabled_and_mieru(self):
        # выключено → False
        self.assertFalse(mieru_dpi.is_mieru_dpi_active())
        # включено, но mieru не установлен (нет mieru.json) → False
        st = mieru_dpi._load_state()
        st["enabled"] = True
        mieru_dpi._save_state(st)
        self.assertFalse(mieru_dpi.is_mieru_dpi_active())
        # включено + mieru установлен → True
        mieru_dpi._MIERU_STATE.write_text(json.dumps({
            "installed": True, "port_start": 2012, "protocol": "TCP",
            "users": [{"username": "alice", "password": "pw"}],
        }))
        self.assertTrue(mieru_dpi.is_mieru_dpi_active())

    def test_get_route_domains(self):
        st = mieru_dpi._load_state()
        st["route_domains"] = ["b.com", "a.com", "b.com"]
        mieru_dpi._save_state(st)
        self.assertEqual(mieru_dpi.get_route_domains(), ["a.com", "b.com"])


class TestNormalizeDomain(unittest.TestCase):
    """_normalize_domain: wildcard → apex, catch-all/мусор → None."""

    def test_wildcard_to_apex(self):
        self.assertEqual(mieru_dpi._normalize_domain("*.youtube.com"), "youtube.com")

    def test_plain_domain(self):
        self.assertEqual(mieru_dpi._normalize_domain("YouTube.COM "), "youtube.com")

    def test_catchall_rejected(self):
        self.assertIsNone(mieru_dpi._normalize_domain("*"))

    def test_regexp_and_garbage_rejected(self):
        self.assertIsNone(mieru_dpi._normalize_domain("regexp:.*\\.ru"))
        self.assertIsNone(mieru_dpi._normalize_domain(""))
        self.assertIsNone(mieru_dpi._normalize_domain("превед медвед"))
        self.assertIsNone(mieru_dpi._normalize_domain("a b.com"))
        self.assertIsNone(mieru_dpi._normalize_domain("http://x.com"))


class TestCollectB4Domains(unittest.TestCase):
    """collect_b4_domains: enabled-сеты → (domains, set_ids)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        _tmp_state_paths(self, self._td.name)

    def tearDown(self):
        mieru_dpi._STATE_FILE = self._old_state
        mieru_dpi._MIERU_STATE = self._old_mieru_state
        self._td.cleanup()

    def test_collect_enabled_sets_only(self):
        fake_sets = [
            {"id": "yt", "enabled": True, "domains": ["youtube.com", "*.googlevideo.com"]},
            {"id": "off", "enabled": False, "domains": ["disabled.com"]},
            {"id": "custom-1", "enabled": True, "domains": ["whatsapp.com", "*"]},
        ]
        with patch.object(mieru_dpi, "_dpi") as fake_dpi:
            fake_dpi.return_value._detect_sets.return_value = fake_sets
            domains, set_ids = mieru_dpi.collect_b4_domains()
        self.assertIn("youtube.com", domains)
        self.assertIn("googlevideo.com", domains)
        self.assertIn("whatsapp.com", domains)
        self.assertNotIn("disabled.com", domains)
        self.assertIn("custom-1", set_ids)
        self.assertNotIn("off", set_ids)

    def test_collect_empty_on_error(self):
        with patch.object(mieru_dpi, "_dpi") as fake_dpi:
            fake_dpi.return_value._detect_sets.side_effect = RuntimeError("boom")
            domains, set_ids = mieru_dpi.collect_b4_domains()
        self.assertEqual(domains, [])
        self.assertEqual(set_ids, [])

    def test_sync_idempotent(self):
        fake_sets = [{"id": "yt", "enabled": True,
                      "domains": ["youtube.com"]}]
        with patch.object(mieru_dpi, "_dpi") as fake_dpi:
            fake_dpi.return_value._detect_sets.return_value = fake_sets
            r1 = mieru_dpi.sync_b4_to_mieru()
            r2 = mieru_dpi.sync_b4_to_mieru()
        self.assertEqual(r1["domains"], 1)
        self.assertTrue(r1["changed"])    # первый синк из пустого state — изменение
        self.assertFalse(r2["changed"])    # повтор — идемпотентно
        self.assertEqual(mieru_dpi.get_route_domains(), ["youtube.com"])
        self.assertEqual(mieru_dpi._load_state()["synced_sets"], ["yt"])


class TestBuildRouteRules(unittest.TestCase):
    """build_mieru_route_rules: формат sing-box route.rules."""

    def test_basic(self):
        rules = mieru_dpi.build_mieru_route_rules(
            "mieru-alice", ["youtube.com", "googlevideo.com"])
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(r["domain_suffix"], ["youtube.com", "googlevideo.com"])
        self.assertEqual(r["action"], "route")
        self.assertEqual(r["outbound"], "mieru-alice")

    def test_empty_inputs(self):
        self.assertEqual(mieru_dpi.build_mieru_route_rules("", ["a.com"]), [])
        self.assertEqual(mieru_dpi.build_mieru_route_rules("tag", []), [])
        self.assertEqual(mieru_dpi.build_mieru_route_rules("", []), [])


class TestKaringSplitConfig(unittest.TestCase):
    """build_karing_split_config: split-конфиг меню [6]."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        _tmp_state_paths(self, self._td.name)
        mieru_dpi._MIERU_STATE.write_text(json.dumps({
            "installed": True,
            "port_start": 2012, "port_end": 2022, "protocol": "TCP",
            "users": [{"username": "alice", "password": "secret"}],
            "traffic_preset": "basic",
            "client_dns": "",
            "client_server_addr": "",
        }))

    def tearDown(self):
        mieru_dpi._STATE_FILE = self._old_state
        mieru_dpi._MIERU_STATE = self._old_mieru_state
        self._td.cleanup()

    def test_split_config_shape(self):
        st = mieru_dpi._load_state()
        st["route_domains"] = ["youtube.com"]
        mieru_dpi._save_state(st)
        with patch.object(mieru_dpi, "_mieru") as fake_m:
            fake_m.return_value._gen_singbox_outbound.return_value = {
                "type": "mieru", "tag": "mieru-alice", "server": "1.2.3.4",
                "server_port": 2012, "transport": "TCP",
                "username": "alice", "password": "secret",
                "multiplexing": "MULTIPLEXING_HIGH",
            }
            fake_m.return_value._dns_host_is_domain.return_value = False
            fake_m.return_value._build_karing_dns_block.return_value = {}
            fake_m.return_value._get_server_ip.return_value = "1.2.3.4"
            cfg = mieru_dpi.build_karing_split_config()
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg["route"]["final"], "direct")
        self.assertEqual(len(cfg["route"]["rules"]), 1)
        self.assertEqual(cfg["route"]["rules"][0]["outbound"], "mieru-alice")
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        self.assertIn("mieru-alice", tags)
        self.assertIn("direct", tags)

    def test_no_users_returns_none(self):
        mieru_dpi._MIERU_STATE.write_text(json.dumps({"installed": True}))
        self.assertIsNone(mieru_dpi.build_karing_split_config())


class TestE2EProbe(unittest.TestCase):
    """_e2e_probe: graceful skip, генерация изолированного конфига."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        _tmp_state_paths(self, self._td.name)

    def tearDown(self):
        mieru_dpi._STATE_FILE = self._old_state
        mieru_dpi._MIERU_STATE = self._old_mieru_state
        mieru_dpi._MIERU_BIN = self._old_bin
        self._td.cleanup()

    def test_skipped_when_no_binary(self):
        self._old_bin = mieru_dpi._MIERU_BIN
        mieru_dpi._MIERU_BIN = Path("/nonexistent/mieru")
        r = mieru_dpi._e2e_probe()
        self.assertFalse(r["available"])
        self.assertIsNone(r["ok"])

    def test_skipped_when_no_users(self):
        self._old_bin = mieru_dpi._MIERU_BIN
        real_bin = mieru_dpi._MIERU_BIN
        mieru_dpi._MIERU_STATE.write_text(json.dumps({"installed": True}))
        # бинарник «есть» (чтобы пройти первый фильтр)
        mieru_dpi._MIERU_BIN = Path("/bin/true")
        try:
            r = mieru_dpi._e2e_probe()
        finally:
            mieru_dpi._MIERU_BIN = real_bin
        self.assertFalse(r["available"])

    def test_client_config_structure(self):
        """Побочно: проверяем содержимое конфига, который E2E скармливает
        mieru apply config (генерация вынесена логикой _e2e_probe —
        тестируем через подмену subprocess.run и чтение temp-файла)."""
        self._old_bin = mieru_dpi._MIERU_BIN
        mieru_dpi._MIERU_BIN = Path("/bin/sh")
        mieru_dpi._MIERU_STATE.write_text(json.dumps({
            "installed": True, "port_start": 2012, "protocol": "TCP",
            "users": [{"username": "bob", "password": "pw"}],
            "traffic_preset": "medium",
        }))
        seen_cfg = {}

        def fake_run(cmd, **kw):
            # перехватываем apply config — читаем файл конфига
            if len(cmd) > 3 and cmd[1] == "apply" and cmd[3].endswith("client.json"):
                seen_cfg.update(json.loads(Path(cmd[3]).read_text()))
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[1] == "test":
                return MagicMock(returncode=0,
                                 stdout="Connected to 1.2.3.4", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        try:
            with patch("subprocess.run", side_effect=fake_run):
                r = mieru_dpi._e2e_probe()
        finally:
            pass
        self.assertTrue(r["available"])
        self.assertTrue(r["ok"])
        # структура клиентского конфига mieru
        self.assertIn("profiles", seen_cfg)
        prof = seen_cfg["profiles"][0]
        self.assertEqual(prof["user"]["name"], "bob")
        self.assertEqual(prof["servers"][0]["ipAddress"], "127.0.0.1")
        self.assertEqual(prof["servers"][0]["portBindings"][0]["port"], 2012)
        # trafficPattern — JSON-форма пресета medium
        self.assertIn("trafficPattern", prof)
        self.assertIn("tcpFragment", prof["trafficPattern"])


class TestMenuMarkers(unittest.TestCase):
    """Маркеры встройки меню (source-level — как TestWhitelistBatchOperations)."""

    def test_core_menu_item_mb_next_to_b(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('_box_item("MB"', src)
        # пункт MB стоит сразу после пункта B (один блок, без разделителя)
        b_pos = src.find('_box_item("B"')
        mb_pos = src.find('_box_item("MB"')
        self.assertGreater(mb_pos, b_pos)
        self.assertLess(mb_pos - b_pos, 400)

    def test_core_handler_mb(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('ch.lower() == "mb"', src)
        self.assertIn("from chimera.modules.mieru_dpi import do_mieru_dpi_menu", src)

    def test_module_public_api(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "mieru_dpi.py").read_text()
        for marker in (
            "def do_mieru_dpi_menu",
            "def sync_b4_to_mieru",
            "def health_check_mieru",
            "def build_mieru_route_rules",
            "def build_karing_split_config",
            "def is_mieru_dpi_active",
            "def collect_b4_domains",
            "def get_mieru_dpi_info",
        ):
            self.assertIn(marker, src)

    def test_subscription_multinode_integration_markers(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "subscription_multinode.py").read_text()
        for marker in (
            "_collect_mieru_outbounds_for_multinode",
            "from chimera.modules import mieru_dpi as _md",
            "node_outbounds.extend(_mobs)",
            "node_tags + extra_tags + mieru_tags + [URLTEST_TAG]",
            "streaming_default = mieru_tags[0]",
            '"domain_suffix": list(mieru_domains)',
            "node_domains + mieru_server_domains",
        ):
            self.assertIn(marker, src)

    def test_subscription_single_branch_marker(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "subscription.py").read_text()
        for marker in (
            "from chimera.modules import mieru_dpi",
            "mieru_dpi.build_mieru_route_rules",
            "_route[\"rules\"] = _md_rules + _existing",
        ):
            self.assertIn(marker, src)


class TestMultinodeIntegration(unittest.TestCase):
    """Мульти-нодовая подписка: mieru-outbound + правила при активном режиме.

    Тестируем через реальный build_singbox_config с подменёнными
    источниками данных (state/collect/mieru_dpi) — как
    test_singbox_multinode_config.py."""

    @classmethod
    def setUpClass(cls):
        cls._saved = {k: sys.modules.get(k) for k in
                      ("chimera", "chimera.modules", "chimera._core",
                       "chimera.modules.subscription_multinode",
                       "chimera.modules.mieru_dpi")}
        _setup_core_in_sysmodules()
        from chimera.modules import subscription_multinode as sm
        cls.sm = sm

    @classmethod
    def tearDownClass(cls):
        for k, v in TestMultinodeIntegration._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    def _build(self, mieru_active: bool, mieru_obs=None, domains=None):
        user = {"uuid": "u-1", "email": "alice@example.com", "name": "alice"}
        nodes = [{
            "name": "NL-Exit-1",
            "host": "203.0.113.136", "port": 443, "uuid": "exit-uuid",
            "pubkey": "pub", "shortid": "abcd", "sni": "cdn.jsdelivr.net",
            "fp": "chrome", "proto": "reality", "label": "NL-Exit-1",
        }]
        reg = {"all": nodes, "entry": {"name": "NL-Exit-1"},
               "exits": [nodes[0]]}
        with patch.object(self.sm, "collect_nodes", return_value=reg), \
             patch.object(self.sm, "is_multinode_active", return_value=True), \
             patch.object(self.sm, "_load_state", return_value={}), \
             patch.object(self.sm, "_singbox_vless_outbound",
                          side_effect=lambda nd: {
                              "type": "vless", "tag": nd["label"],
                              "server": nd["host"], "server_port": nd["port"],
                          }), \
             patch.object(self.sm, "_collect_mieru_outbounds_for_multinode",
                          return_value=(mieru_obs or [])), \
             patch("chimera.modules.mieru_dpi.is_mieru_dpi_active",
                   return_value=mieru_active), \
             patch("chimera.modules.mieru_dpi.get_route_domains",
                   return_value=(domains or [])):
            return self.sm.build_singbox_config(user)

    def test_mieru_off_no_changes(self):
        body = self._build(mieru_active=False)
        cfg = json.loads(body)
        tags = [ob["tag"] for ob in cfg["outbounds"] if ob.get("type") == "mieru"]
        self.assertEqual(tags, [])
        # правила mieru отсутствуют
        for r in cfg["route"]["rules"]:
            self.assertNotEqual(r.get("outbound"), "mieru-alice")

    def test_mieru_active_full_integration(self):
        obs = [{"type": "mieru", "tag": "mieru-alice", "server": "chimera.ru",
                "server_port": 2012, "transport": "TCP",
                "username": "alice", "password": "pw",
                "multiplexing": "MULTIPLEXING_HIGH"}]
        body = self._build(mieru_active=True, mieru_obs=obs,
                           domains=["youtube.com", "googlevideo.com"])
        cfg = json.loads(body)
        # 1. mieru-outbound в конфиге
        mieru_obs_cfg = [ob for ob in cfg["outbounds"]
                         if ob.get("type") == "mieru"]
        self.assertEqual(len(mieru_obs_cfg), 1)
        # 2. mieru в главном selector
        selector = next(ob for ob in cfg["outbounds"]
                        if ob.get("type") == "selector" and ob["tag"] == "🎯 Chimera")
        self.assertIn("mieru-alice", selector["outbounds"])
        # 3. mieru в Streaming-группе, дефолт — mieru
        streaming = next(ob for ob in cfg["outbounds"]
                         if ob.get("type") == "selector" and "Streaming" in ob["tag"])
        self.assertEqual(streaming["default"], "mieru-alice")
        self.assertEqual(streaming["outbounds"][0], "mieru-alice")
        # 4. route-правило доменов ВЫШЕ streaming-группы
        rules = cfg["route"]["rules"]
        mieru_rule_idx = next(i for i, r in enumerate(rules)
                              if r.get("outbound") == "mieru-alice")
        streaming_rule_idx = next(i for i, r in enumerate(rules)
                                  if r.get("outbound") == self.sm.STREAMING_TAG)
        self.assertLess(mieru_rule_idx, streaming_rule_idx)
        self.assertEqual(rules[mieru_rule_idx]["domain_suffix"],
                         ["youtube.com", "googlevideo.com"])
        # 5. домен mita в protect (domain_suffix → direct до правила mieru)
        protect_rule = next(r for r in rules
                            if r.get("outbound") == "direct"
                            and "chimera.ru" in (r.get("domain_suffix") or []))
        protect_idx = rules.index(protect_rule)
        self.assertLess(protect_idx, mieru_rule_idx)
        # 6. домен mita в DNS local (защита от fakeip-петли)
        dns_rules = cfg["dns"]["rules"]
        self.assertTrue(any("chimera.ru" in (r.get("domain_suffix") or [])
                            and r.get("server") == "local-dns"
                            for r in dns_rules))

    def test_mieru_active_no_user_match(self):
        """Пользователь без привязки mieru-креда → конфиг без mieru (санитайз)."""
        body = self._build(mieru_active=True, mieru_obs=[])
        cfg = json.loads(body)
        tags = [ob["tag"] for ob in cfg["outbounds"] if ob.get("type") == "mieru"]
        self.assertEqual(tags, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
