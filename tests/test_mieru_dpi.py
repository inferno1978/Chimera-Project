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
  8. _mierus_links_for_state: записи ПО ЮЗЕРАМ с метками форматов
     (karing/nekobox) + редизайн [6]: ссылки/JSON ВНЕ рамок (маркеры)
  9. _e2e_probe: генерация клиентского конфига (изоляция HOME,
     trafficPattern JSON-формой), недоступность = graceful skip,
     флоу apply → start(Popen) → ss-готовность → test → stop,
     не-подъём демона, kill застрявшего родителя (форк-баг start)
 10. Интеграция подписки (мульти-нодовая): mieru-outbound в selector +
     Streaming, route-правила ВЫШЕ geosite, protect домена mita
 11. Интеграция подписки (одиночная): route.rules → mieru-outbound
 12. Маркеры меню: пункт [MB] в _core.py рядом с [B]
"""
from __future__ import annotations

import json
import subprocess
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


class TestNyameboxSplitConfig(unittest.TestCase):
    """build_nyamebox_split_config / _nyamebox_dns_block: формат 1.13.x.

    NyameBox (qr243vbi/nekobox) — ядро sing-box 1.13.19: DNS в формате
    1.12+ (type-серверы), local-DNS без detour, mieru-outbound без mtu.
    Все три нюанса пойманы живым nekobox_core 5.11.28.3 (check/run/E2E,
    01.10.2026): strict-decode «unknown field mtu», FATAL «detour to an
    empty direct outbound» (run, не check), deprecation-WARN
    default_domain_resolver.

    Тег mieru-outbound — «proxy»: конвенция ПРИЛОЖЕНИЯ, при старте
    Custom-профиля оно заменяет DNS на свой remote_dns с жёстко
    зашитым detour="proxy" (ConfigBuilder.cpp:118; разбор активации
    01.10.2026 — скриншот юзера «transport must be TCP or UDP»)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        _tmp_state_paths(self, self._td.name)
        mieru_dpi._MIERU_STATE.write_text(json.dumps({
            "installed": True,
            "port_start": 2012, "port_end": 2022, "protocol": "TCP",
            "users": [{"username": "alice", "password": "secret"}],
            "traffic_preset": "basic",
            "client_dns": "https://dns.example.com:30443/dns-query",
            "client_server_addr": "",
        }))

    def tearDown(self):
        mieru_dpi._STATE_FILE = self._old_state
        mieru_dpi._MIERU_STATE = self._old_mieru_state
        self._td.cleanup()

    @staticmethod
    def _fake_mieru():
        fake = MagicMock()
        fake._get_server_ip.return_value = "1.2.3.4"
        fake._dns_host_is_domain.return_value = True
        fake._gen_singbox_outbound.return_value = {
            "type": "mieru", "tag": "mieru-alice", "server": "1.2.3.4",
            "server_port": 2012, "transport": "TCP",
            "username": "alice", "password": "secret",
            "multiplexing": "MULTIPLEXING_HIGH",
        }
        # legacy-DNS блок, как его собирает mieru._build_karing_dns_block
        fake._build_karing_dns_block.return_value = {
            "servers": [
                {"tag": "custom-dns",
                 "address": "https://dns.example.com:30443/dns-query",
                 "detour": "mieru-alice", "address_resolver": "local"},
                {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
            ],
        }
        return fake

    def test_dns_modern_format(self):
        """DNS: type-серверы 1.12+ (без address), local без detour,
        final = первый сервер; домен резолвера bootstrap-ится local."""
        with patch.object(mieru_dpi, "_mieru",
                          return_value=self._fake_mieru()):
            cfg = mieru_dpi.build_nyamebox_split_config()
        self.assertIsNotNone(cfg)
        servers = cfg["dns"]["servers"]
        self.assertEqual(servers[0]["type"], "https")
        self.assertEqual(servers[0]["server"], "dns.example.com")
        self.assertEqual(servers[0]["server_port"], 30443)
        self.assertEqual(servers[0]["path"], "/dns-query")
        self.assertEqual(servers[0]["detour"], "proxy")  # конвенция приложения
        self.assertEqual(servers[0]["domain_resolver"], "local")
        self.assertNotIn("address", servers[0])  # legacy-поля нет
        self.assertEqual(servers[1],
                         {"type": "udp", "tag": "local", "server": "1.1.1.1"})
        self.assertNotIn("detour", servers[1])  # иначе FATAL при старте
        self.assertEqual(cfg["dns"]["final"], "custom-dns")

    def test_route_and_parity(self):
        """route: final=direct + auto_detect_interface +
        default_domain_resolver=первый DNS; mieru БЕЗ mtu; домены
        и креды маршрутки == Karing-варианту 1:1."""
        st = mieru_dpi._load_state()
        st["route_domains"] = ["youtube.com", "t.me"]
        mieru_dpi._save_state(st)
        with patch.object(mieru_dpi, "_mieru",
                          return_value=self._fake_mieru()):
            nyame = mieru_dpi.build_nyamebox_split_config()
            karing = mieru_dpi.build_karing_split_config()
        self.assertIsNotNone(nyame)
        self.assertEqual(nyame["route"]["final"], "direct")
        self.assertTrue(nyame["route"]["auto_detect_interface"])
        self.assertEqual(nyame["route"]["default_domain_resolver"],
                         "custom-dns")
        # домены — 1:1 с Karing; outbound-ссылка — на «proxy» (не тег
        # Karing-варианта): см. конвенцию в докстринге класса
        self.assertEqual(nyame["route"]["rules"][0]["domain_suffix"],
                         karing["route"]["rules"][0]["domain_suffix"])
        self.assertEqual(nyame["route"]["rules"][0]["outbound"], "proxy")
        mieru_ob = next(o for o in nyame["outbounds"]
                        if o.get("type") == "mieru")
        self.assertNotIn("mtu", mieru_ob)  # релиз 5.11.28.3 не знает поля
        self.assertEqual(mieru_ob["username"], "alice")
        self.assertEqual(mieru_ob["multiplexing"], "MULTIPLEXING_HIGH")

    def test_none_when_not_installed(self):
        """Mieru/юзеров нет → None (паритет с Karing-вариантом)."""
        mieru_dpi._MIERU_STATE.write_text(
            json.dumps({"installed": True, "users": []}))
        self.assertIsNone(mieru_dpi.build_nyamebox_split_config())

    def test_proxy_tag_convention(self):
        """Активация в приложении: тег mieru = "proxy" и НИ ОДНОЙ
        висячей ссылки — детур DNS и route-правила указывают на
        существующий outbound; Karing-вариант при этом не тронут
        (его тег остаётся из генератора, напр. "mieru-alice")."""
        st = mieru_dpi._load_state()
        st["route_domains"] = ["youtube.com"]
        mieru_dpi._save_state(st)
        with patch.object(mieru_dpi, "_mieru",
                          return_value=self._fake_mieru()):
            nyame = mieru_dpi.build_nyamebox_split_config()
            karing = mieru_dpi.build_karing_split_config()
        self.assertIsNotNone(nyame)
        mieru_ob = next(o for o in nyame["outbounds"]
                        if o.get("type") == "mieru")
        self.assertEqual(mieru_ob["tag"], "proxy")
        # Karing-вариант не задет: тег из генератора на месте
        karing_ob = next(o for o in karing["outbounds"]
                         if o.get("type") == "mieru")
        self.assertEqual(karing_ob["tag"], "mieru-alice")
        # все ссылки в nyame-конфиге указывают на существующие теги
        tags = {o["tag"] for o in nyame["outbounds"]}
        for r in nyame["route"].get("rules") or []:
            self.assertIn(r.get("outbound"), tags)
        self.assertIn(nyame["route"]["final"], tags)
        for s in nyame["dns"]["servers"]:
            if s.get("detour"):
                self.assertIn(s["detour"], tags)

    def test_clash_api_dummy(self):
        """Волна 4 активации: работающий Custom-профиль без clash_api
        заспамлен «no clash server found» — ConnectionLister каждую
        секунду зовёт ListConnections (настройка «Connection
        statistics», дефолт ON), а full-конфиг приложение пускает
        как есть, experimental не добавляя. Генератор теперь вставляет
        dummy clash_api — ровно как приложение для нативных профилей
        (ConfigBuilder.cpp:1725-1744): без external_controller (порт
        не слушается), Karing-вариант не задет."""
        st = mieru_dpi._load_state()
        st["route_domains"] = ["youtube.com"]
        mieru_dpi._save_state(st)
        with patch.object(mieru_dpi, "_mieru",
                          return_value=self._fake_mieru()):
            nyame = mieru_dpi.build_nyamebox_split_config()
            karing = mieru_dpi.build_karing_split_config()
        self.assertIsNotNone(nyame)
        # dummy на месте и ровно в форме приложения
        self.assertEqual(nyame.get("experimental"),
                         {"clash_api": {"default_mode": ""}})
        # без external_controller — порт не слушается, конфликтов нет
        clash = nyame["experimental"]["clash_api"]
        self.assertNotIn("external_controller", clash)
        # Karing-вариант не задет — блок только у NyameBox
        self.assertNotIn("experimental", karing)


class TestMierusLinksForState(unittest.TestCase):
    """_mierus_links_for_state: записи по юзерам с метками форматов.

    Раньше функция возвращала плоский список ссылок без подписей
    (Karing- и Nekobox-форматы вперемешку). После редизайна [6] —
    запись на юзера×транспорт с ключами user/proto/karing/nekobox."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        _tmp_state_paths(self, self._td.name)

    def tearDown(self):
        mieru_dpi._STATE_FILE = self._old_state
        mieru_dpi._MIERU_STATE = self._old_mieru_state
        self._td.cleanup()

    def _set_state(self, users, protocol="TCP"):
        mieru_dpi._MIERU_STATE.write_text(json.dumps({
            "installed": True, "port_start": 2012, "port_end": 2022,
            "protocol": protocol, "users": users,
            "traffic_preset": "basic", "client_server_addr": "1.2.3.4",
        }))

    @staticmethod
    def _fake_mieru():
        fake = MagicMock()
        fake._get_server_ip.return_value = "1.2.3.4"
        fake._dns_host_is_domain.return_value = False
        fake._gen_client_share_link.side_effect = \
            lambda ip, p1, p2, proto, u, pw, traffic_preset="": \
                f"KARING|{u}|{proto}"
        fake._gen_client_share_link_nekobox.side_effect = \
            lambda ip, p, proto, u, pw: f"NEKOBOX|{u}|{proto}"
        return fake

    def test_entries_labeled_per_user(self):
        """Юзер → запись с обоими форматами под явными ключами."""
        self._set_state([{"username": "admin", "password": "a"},
                         {"username": "user", "password": "b"}])
        with patch.object(mieru_dpi, "_mieru",
                          return_value=self._fake_mieru()):
            entries = mieru_dpi._mierus_links_for_state()
        self.assertEqual([e["user"] for e in entries], ["admin", "user"])
        self.assertTrue(all(e["proto"] == "TCP" for e in entries))
        self.assertEqual(entries[0]["karing"], "KARING|admin|TCP")
        self.assertEqual(entries[0]["nekobox"], "NEKOBOX|admin|TCP")
        self.assertEqual(entries[1]["karing"], "KARING|user|TCP")
        self.assertEqual(entries[1]["nekobox"], "NEKOBOX|user|TCP")

    def test_both_protocols_per_user(self):
        """protocol=BOTH → по записи на каждый транспорт."""
        self._set_state([{"username": "u1", "password": "p"}], protocol="BOTH")
        with patch.object(mieru_dpi, "_mieru",
                          return_value=self._fake_mieru()):
            entries = mieru_dpi._mierus_links_for_state()
        self.assertEqual([(e["user"], e["proto"]) for e in entries],
                         [("u1", "TCP"), ("u1", "UDP")])

    def test_empty_when_not_installed(self):
        mieru_dpi._MIERU_STATE.write_text(json.dumps({"installed": False}))
        self.assertEqual(mieru_dpi._mierus_links_for_state(), [])


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

    def _probe_env(self, users=None):
        """Общее для E2E-тестов: подмена бинарника + стейт с юзером."""
        self._old_bin = mieru_dpi._MIERU_BIN
        mieru_dpi._MIERU_BIN = Path("/bin/sh")
        mieru_dpi._MIERU_STATE.write_text(json.dumps({
            "installed": True, "port_start": 2012, "protocol": "TCP",
            "users": users or [{"username": "bob", "password": "pw"}],
            "traffic_preset": "medium",
        }))

    @staticmethod
    def _fake_runner(seen_cfg=None, calls=None, socks_up=True,
                     test_out="Connected to 1.2.3.4"):
        """Фейковый subprocess.run: apply/stop/test/ss/status."""

        def fake_run(cmd, **kw):
            if calls is not None:
                calls.append("ss" if cmd[0] == "ss" else cmd[1])
            if (len(cmd) > 3 and cmd[1] == "apply"
                    and cmd[3].endswith("client.json")):
                if seen_cfg is not None:
                    seen_cfg.update(json.loads(Path(cmd[3]).read_text()))
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[0] == "ss":
                stdout = (f"LISTEN 0 128 127.0.0.1:39865 *:*"
                          if socks_up else "")
                return MagicMock(returncode=0, stdout=stdout, stderr="")
            if cmd[1] == "test":
                return MagicMock(returncode=0, stdout=test_out, stderr="")
            if cmd[1] == "status":
                return MagicMock(returncode=1,
                                 stdout="mieru client is not running",
                                 stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        return fake_run

    def test_client_config_structure(self):
        """Побочно: проверяем содержимое конфига, который E2E скармливает
        mieru apply config, И полный флоу пробы: apply → stop-гигиена →
        Popen(start) → ss-готовность → test → stop (генерация вынесена
        логикой _e2e_probe — тестируем через подмену subprocess и чтение
        temp-файла)."""
        seen_cfg, calls = {}, []
        self._probe_env()
        popen = MagicMock()
        try:
            with patch("subprocess.run",
                       side_effect=self._fake_runner(seen_cfg, calls)), \
                 patch("subprocess.Popen", popen), \
                 patch("time.sleep"):
                r = mieru_dpi._e2e_probe()
        finally:
            pass
        self.assertTrue(r["available"])
        self.assertTrue(r["ok"])
        # флоу: apply → stop(гигиена) → [Popen start] → ss → test → stop
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(popen.call_args[0][0][1:], ["start"])
        self.assertEqual(calls, ["apply", "stop", "ss", "test", "stop"])
        # структура клиентского конфига mieru
        self.assertIn("profiles", seen_cfg)
        prof = seen_cfg["profiles"][0]
        self.assertEqual(prof["user"]["name"], "bob")
        self.assertEqual(prof["servers"][0]["ipAddress"], "127.0.0.1")
        self.assertEqual(prof["servers"][0]["portBindings"][0]["port"], 2012)
        # trafficPattern — JSON-форма пресета medium
        self.assertIn("trafficPattern", prof)
        self.assertIn("tcpFragment", prof["trafficPattern"])

    def test_not_ready_reports_failure(self):
        """Демон не поднялся (ss не видит socks5-порт) → available=True,
        ok=False, detail поясняет причину; родитель reap'ается."""
        self._probe_env()
        popen = MagicMock()
        old_to = mieru_dpi._E2E_START_TIMEOUT
        mieru_dpi._E2E_START_TIMEOUT = 0          # цикл готовности не крутится
        try:
            with patch("subprocess.run",
                       side_effect=self._fake_runner(socks_up=False)), \
                 patch("subprocess.Popen", popen), \
                 patch("time.sleep"):
                r = mieru_dpi._e2e_probe()
        finally:
            mieru_dpi._E2E_START_TIMEOUT = old_to
        self.assertTrue(r["available"])
        self.assertFalse(r["ok"])
        self.assertIn("не поднялся", r["detail"])
        self.assertIn("not running", r["detail"])
        popen.return_value.wait.assert_called()   # reap родителя

    def test_stuck_start_parent_killed(self):
        """Форк-баг mieru start: родитель не вышел после stop →
        wait(timeout=5) истекает → kill() страховкой."""
        self._probe_env()
        popen = MagicMock()
        popen.return_value.wait.side_effect = subprocess.TimeoutExpired(
            cmd="mieru start", timeout=5)
        try:
            with patch("subprocess.run",
                       side_effect=self._fake_runner()), \
                 patch("subprocess.Popen", popen), \
                 patch("time.sleep"):
                r = mieru_dpi._e2e_probe()
        finally:
            pass
        self.assertTrue(r["available"])
        self.assertTrue(r["ok"])                  # тест прошёл — уборка не мешает
        popen.return_value.kill.assert_called_once()


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

    def test_client_configs_ux_outside_boxes(self):
        """Редизайн [6]: мини-меню, шпаргалка «что куда», подписи форматов;
        ссылки и JSON печатаются ПОСЛЕ закрытия рамки (_box_bottom
        раньше вывода) — рамки больше не ломаются."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "mieru_dpi.py").read_text()
        for marker in (
            "def _show_client_links",
            "def _show_client_json",
            "_SPLIT_CFG_PATH",
            "Что куда вставлять",
            "Karing (sing-box core)",
            "NekoBox / Nyamebox",
        ):
            self.assertIn(marker, src)
        # JSON — ПОД закрытой рамкой: _box_bottom раньше печати конфига
        fn_j = src[src.find("def _show_client_json"):src.find("def _menu_b4_logs")]
        self.assertLess(fn_j.find("_box_bottom()"),
                        fn_j.find("print(json.dumps(cfg"))
        # ссылки — ПОД закрытой рамкой: _box_bottom раньше печати ссылок
        fn_l = src[src.find("def _show_client_links"):src.find("def _show_client_json")]
        self.assertLess(fn_l.find("_box_bottom()"), fn_l.find("e['karing']"))


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
