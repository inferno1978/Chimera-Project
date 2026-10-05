"""
tests/test_sni_hygiene.py — SNI/dest-гигиена.

Требование владельца: домены известных ресурсов (Microsoft/Cloudflare/Google/
Яндекс и т.п.) НЕ должны фигурировать в SNI/dest по умолчанию — приоритет
СВОЙ домен (Self-SNI: IP↔домен↔сертификат совпадают). Причина: РФ-хостинги
вносят в ToS блокировку серверов с маскарадом под известные ресурсы, РКН
фиксирует несоответствие SNI и владельца IP. Известные домены остаются
ТОЛЬКО как явная кастомизация (справочник + предупреждения).
"""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from chimera.modules import sni_hygiene
from chimera.modules.sni_hygiene import (
    KNOWN_SNI_DOMAINS, REALITY_DEST_BROKEN,
    is_known_resource_domain, is_broken_reality_dest,
    own_masking_domain, warn_known_domain_text,
    client_sni_for_state, reality_self_sni, reality_server_settings,
)


class TestKnownDomainDetection(unittest.TestCase):
    def test_known_domains_detected(self):
        for dom in ("www.cloudflare.com", "cloudflare.com",
                    "cdn.cloudflare.com", "www.microsoft.com",
                    "cdn.microsoft.com", "www.google.com",
                    "googletagmanager.com", "ya.ru", "mail.yandex.ru",
                    "vk.com", "www.bing.com", "www.apple.com"):
            self.assertTrue(is_known_resource_domain(dom), dom)

    def test_own_domains_not_flagged(self):
        for dom in ("my-site.ru", "vpn.example.org", "mysite.duckdns.org",
                    "node1.my-vps.net", "a.b.c.ddns.net"):
            self.assertFalse(is_known_resource_domain(dom), dom)

    def test_host_port_and_url_forms(self):
        self.assertTrue(is_known_resource_domain("www.cloudflare.com:443"))
        self.assertTrue(is_known_resource_domain("https://www.cloudflare.com/"))
        self.assertFalse(is_known_resource_domain("https://my-site.ru/"))

    def test_broken_reality_dest(self):
        self.assertTrue(is_broken_reality_dest("www.microsoft.com"))
        self.assertTrue(is_broken_reality_dest("microsoft.com"))
        self.assertFalse(is_broken_reality_dest("www.cloudflare.com"))
        self.assertFalse(is_broken_reality_dest("my.ru"))

    def test_warning_text_mentions_rkn_and_tos(self):
        txt = warn_known_domain_text("www.cloudflare.com")
        self.assertIn("ToS", txt)
        self.assertIn("РКН", txt)

    def test_warning_for_broken_dest_mentions_cert_limit(self):
        txt = warn_known_domain_text("www.microsoft.com")
        self.assertIn("8192", txt)


class TestOwnMaskingDomain(unittest.TestCase):
    def test_own_domain_from_state(self):
        self.assertEqual(own_masking_domain({"domain": "My.Site.RU"}), "my.site.ru")
        self.assertEqual(own_masking_domain({"domain": "vpn.example.com:443"}),
                         "vpn.example.com")

    def test_no_domain(self):
        self.assertEqual(own_masking_domain({}), "")
        self.assertEqual(own_masking_domain({"domain": ""}), "")
        self.assertEqual(own_masking_domain(None), "")


class TestClientSniCanonicalRule(unittest.TestCase):
    """Канонический SNI-рул клиента (единый для fragment/linkqr/rest_api)."""

    def test_mode_a_uses_domain(self):
        self.assertEqual(
            client_sni_for_state({"domain": "d.ru", "reality_dest": "cf.com"}),
            "d.ru")

    def test_mode_b_awg_uses_reality_dest(self):
        self.assertEqual(
            client_sni_for_state({"domain": "d.ru", "awg_exit_enabled": True,
                                  "install_mode": "B",
                                  "reality_dest": "cf.com:443"}),
            "cf.com")

    def test_mode_b_without_dest_falls_back_to_domain(self):
        self.assertEqual(
            client_sni_for_state({"domain": "d.ru", "awg_exit_enabled": True,
                                  "install_mode": "B"}),
            "d.ru")

    def test_self_sni_mode_b_client_sni_is_own_domain(self):
        # Mode B + reality_dest = свой домен → SNI клиента = свой домен
        self.assertEqual(
            client_sni_for_state({"domain": "d.ru", "awg_exit_enabled": True,
                                  "install_mode": "B", "reality_dest": "d.ru"}),
            "d.ru")

    def test_empty_state(self):
        self.assertEqual(client_sni_for_state({}), "")


class TestRealitySelfSni(unittest.TestCase):
    def test_self_dest_detected(self):
        self.assertTrue(reality_self_sni("my.ru:443", "my.ru"))
        self.assertTrue(reality_self_sni("my.ru", "MY.RU"))

    def test_foreign_dest(self):
        self.assertFalse(reality_self_sni("cf.com", "my.ru"))
        self.assertFalse(reality_self_sni("", "my.ru"))

    def test_no_own_domain(self):
        self.assertFalse(reality_self_sni("my.ru", ""))


class TestRealityServerSettings(unittest.TestCase):
    """dest/xver/serverNames REALITY-inbound — единая точка правды."""

    def test_mode_a_classic(self):
        s = reality_server_settings(False, "", "my.ru", "/dev/shm/x.socket")
        self.assertEqual(s["dest"], "/dev/shm/x.socket")
        self.assertEqual(s["xver"], 1)
        self.assertEqual(s["serverNames"], ["my.ru"])

    def test_mode_b_foreign_dest(self):
        s = reality_server_settings(True, "cf.com", "my.ru", "/dev/shm/x.socket")
        self.assertEqual(s["dest"], "cf.com:443")
        self.assertEqual(s["xver"], 0)
        self.assertEqual(s["serverNames"], ["cf.com"])

    def test_mode_b_self_sni_uses_socket(self):
        # Self-SNI: dest = nginx-сокет (НЕ domain:443 — иначе петля),
        # serverNames = свой домен, xver=1 (PP для nginx)
        s = reality_server_settings(True, "my.ru:443", "my.ru",
                                    "/dev/shm/x.socket")
        self.assertEqual(s["dest"], "/dev/shm/x.socket")
        self.assertEqual(s["xver"], 1)
        self.assertEqual(s["serverNames"], ["my.ru"])


class TestFragmentSniRegression(unittest.TestCase):
    """fragment-модули используют канонический рул (багфикс Mode A)."""

    def setUp(self):
        import sys
        core_path = Path(__file__).resolve().parent.parent / "chimera" / "_core.py"
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
        import tempfile
        import shutil
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._frag_dir = self._tmpdir / "fragment"
        self._frag_dir.mkdir()
        self._shutil = shutil

    def tearDown(self):
        self._shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _frag_cfg(self, module_state):
        from chimera.modules import fragment_config as fc
        self._state.write_text(json.dumps(module_state))
        with patch.object(fc, "_STATE_FILE", self._state), \
             patch.object(fc, "_FRAGMENT_DIR", self._frag_dir):
            res = fc.generate_fragment_client_config("1-3", "3-7", "10-20")
        if res is None:
            return None
        return json.loads(res.read_text())

    def test_fragment_reality_mode_a_sni_domain(self):
        cfg = self._frag_cfg({
            "domain": "vpn.example.com", "uuid": "u",
            "protocol_mode": "reality", "reality_dest": "cf.example.com:443",
            "reality_pubkey": "PUB", "reality_privkey": "PRIV",
            "reality_shortid": "sid",
        })
        self.assertIsNotNone(cfg)
        rs = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
        # Mode A: SNI = свой домен (не reality_dest, не cloudflare-фолбэк)
        self.assertEqual(rs["serverName"], "vpn.example.com")

    def test_fragment_reality_mode_b_awg_sni_dest(self):
        cfg = self._frag_cfg({
            "domain": "vpn.example.com", "uuid": "u",
            "protocol_mode": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "cf.example.com:443",
            "reality_pubkey": "PUB", "reality_privkey": "PRIV",
            "reality_shortid": "sid",
        })
        self.assertIsNotNone(cfg)
        rs = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["serverName"], "cf.example.com")


class TestShadowtlsHandshakeDefault(unittest.TestCase):
    def test_own_domain_preferred(self):
        import chimera.modules.singbox_common as sc
        with patch.object(sc, "_load_main_state",
                          return_value={"domain": "my.ru"}):
            self.assertEqual(sc.shadowtls_handshake_default(), "my.ru")

    def test_fallback_constant_when_no_domain(self):
        import chimera.modules.singbox_common as sc
        with patch.object(sc, "_load_main_state", return_value={}):
            self.assertEqual(sc.shadowtls_handshake_default(),
                             sc.DEFAULT_SHADOWTLS_HANDSHAKE_HOST)


class TestNaiveFakeUrlDefault(unittest.TestCase):
    def test_own_domain_preferred(self):
        import json
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import chimera.modules.naiveproxy as np
        with TemporaryDirectory() as td:
            # _MODULE_STATE = /var/lib/xray-installer/naiveproxy.json →
            # main state = parent/state.json
            fake_state = Path(td) / "naiveproxy.json"
            (Path(td) / "state.json").write_text(json.dumps({"domain": "my.ru"}))
            with patch.object(np, "_MODULE_STATE", fake_state):
                self.assertEqual(np._fake_url_default(), "https://my.ru/")

    def test_bing_only_without_domain(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import chimera.modules.naiveproxy as np
        with TemporaryDirectory() as td:
            fake_state = Path(td) / "naiveproxy.json"
            with patch.object(np, "_MODULE_STATE", fake_state):
                self.assertEqual(np._fake_url_default(), "https://www.bing.com")


class TestKnownDomainsReferenceIntegrity(unittest.TestCase):
    def test_reference_nonempty_and_categorized(self):
        self.assertGreaterEqual(len(KNOWN_SNI_DOMAINS), 5)
        for dom, cat, note in KNOWN_SNI_DOMAINS:
            self.assertTrue(dom)
            self.assertTrue(cat)
            self.assertIn(".", dom)

    def test_broken_list_is_subset_of_known(self):
        for b in REALITY_DEST_BROKEN:
            self.assertTrue(is_known_resource_domain(b), b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
