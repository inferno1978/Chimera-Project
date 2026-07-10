#!/usr/bin/env python3
"""
tests/test_wave5_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для mirror-реестров и specs Волны 5:
  • awg_cascade_mirrors.py + awg_cascade_packages.py::RU_ZONE_SPEC
  • slipgate_mirrors.py + slipgate_packages.py::SLIPGATE_INSTALLER_SPEC
  • telemt_geoip_mirrors.py + telemt_geoip_packages.py::*_SPEC
  • iperf3_mirrors.py + iperf3_packages.py::IPERF3_SPEC
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


# ============================================================================
#  awg_cascade_mirrors — ru.zone
# ============================================================================
class TestAwgCascadeMirrors(unittest.TestCase):
    """awg_cascade_mirrors — 9 зеркал для ru.zone (ipdeny + raw + 7 proxy)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_9_urls(self):
        from vless_installer.modules.awg_cascade_mirrors import (
            get_ru_zone_mirrors, RU_ZONE_MIRRORS_COUNT,
        )
        urls = get_ru_zone_mirrors()
        self.assertEqual(len(urls), 9)
        self.assertEqual(RU_ZONE_MIRRORS_COUNT, 9)

    def test_all_urls_are_https(self):
        from vless_installer.modules.awg_cascade_mirrors import get_ru_zone_mirrors
        for url in get_ru_zone_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_first_url_is_ipdeny(self):
        from vless_installer.modules.awg_cascade_mirrors import get_ru_zone_mirrors
        urls = get_ru_zone_mirrors()
        self.assertIn("ipdeny.com", urls[0])

    def test_has_github_raw_fallback(self):
        from vless_installer.modules.awg_cascade_mirrors import get_ru_zone_mirrors
        urls = get_ru_zone_mirrors()
        self.assertTrue(any("raw.githubusercontent.com" in u for u in urls))

    def test_has_gh_proxy(self):
        from vless_installer.modules.awg_cascade_mirrors import get_ru_zone_mirrors
        urls = get_ru_zone_mirrors()
        proxy_domains = ["ghproxy", "gh.con.sh", "gitmirror", "moeyy", "ghps.cc"]
        has_proxy = any(any(d in u for d in proxy_domains) for u in urls)
        self.assertTrue(has_proxy)

    def test_recommended_manual_path_is_root(self):
        from vless_installer.modules.awg_cascade_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


class TestRuZoneSpecSanity(unittest.TestCase):
    """Sanity-проверки RU_ZONE_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_ru_zone(self):
        from vless_installer.modules.awg_cascade_packages import RU_ZONE_SPEC
        self.assertEqual(RU_ZONE_SPEC.name, "ru.zone")

    def test_filename_is_ru_zone(self):
        from vless_installer.modules.awg_cascade_packages import RU_ZONE_SPEC
        self.assertEqual(RU_ZONE_SPEC.filename_builder(), "ru.zone")

    def test_manual_dir_is_root(self):
        from vless_installer.modules.awg_cascade_packages import RU_ZONE_SPEC
        self.assertEqual(RU_ZONE_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.awg_cascade_packages import RU_ZONE_SPEC
        for dest in RU_ZONE_SPEC.install_dests:
            self.assertNotEqual(RU_ZONE_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_1kb(self):
        from vless_installer.modules.awg_cascade_packages import RU_ZONE_SPEC
        self.assertEqual(RU_ZONE_SPEC.min_size, 1000)

    def test_post_install_is_set(self):
        from vless_installer.modules.awg_cascade_packages import RU_ZONE_SPEC
        self.assertIsNotNone(RU_ZONE_SPEC.post_install)


# ============================================================================
#  slipgate_mirrors
# ============================================================================
class TestSlipgateMirrors(unittest.TestCase):
    """slipgate_mirrors — 13 зеркал для install.sh."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_13_urls(self):
        from vless_installer.modules.slipgate_mirrors import (
            get_slipgate_installer_mirrors, SLIPGATE_INSTALLER_MIRRORS_COUNT,
        )
        urls = get_slipgate_installer_mirrors()
        self.assertEqual(len(urls), 13)
        self.assertEqual(SLIPGATE_INSTALLER_MIRRORS_COUNT, 13)

    def test_all_urls_are_https(self):
        from vless_installer.modules.slipgate_mirrors import get_slipgate_installer_mirrors
        for url in get_slipgate_installer_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_filename(self):
        from vless_installer.modules.slipgate_mirrors import get_slipgate_installer_mirrors
        for url in get_slipgate_installer_mirrors():
            self.assertIn("anonvector", url)
            self.assertIn("slipgate", url)
            self.assertIn("install.sh", url)

    def test_has_raw_github_url(self):
        from vless_installer.modules.slipgate_mirrors import get_slipgate_installer_mirrors
        urls = get_slipgate_installer_mirrors()
        self.assertTrue(any("raw.githubusercontent.com" in u for u in urls))


class TestSlipgateSpecSanity(unittest.TestCase):
    """Sanity-проверки SLIPGATE_INSTALLER_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_slipgate_install_sh(self):
        from vless_installer.modules.slipgate_packages import SLIPGATE_INSTALLER_SPEC
        self.assertEqual(SLIPGATE_INSTALLER_SPEC.name, "SlipGate install.sh")

    def test_filename_is_install_sh(self):
        from vless_installer.modules.slipgate_packages import SLIPGATE_INSTALLER_SPEC
        self.assertEqual(SLIPGATE_INSTALLER_SPEC.filename_builder(), "install.sh")

    def test_manual_dir_is_root(self):
        from vless_installer.modules.slipgate_packages import SLIPGATE_INSTALLER_SPEC
        self.assertEqual(SLIPGATE_INSTALLER_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.slipgate_packages import SLIPGATE_INSTALLER_SPEC
        for dest in SLIPGATE_INSTALLER_SPEC.install_dests:
            self.assertNotEqual(SLIPGATE_INSTALLER_SPEC.manual_incoming_dir, dest)


# ============================================================================
#  telemt_geoip_mirrors
# ============================================================================
class TestTelemtGeoipMirrors(unittest.TestCase):
    """telemt_geoip_mirrors — 5 CDN зеркал для .mmdb.gz."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_city_mirrors_count(self):
        from vless_installer.modules.telemt_geoip_mirrors import (
            get_telemt_geoip_city_mirrors, TELEMT_GEOIP_MIRRORS_COUNT,
        )
        urls = get_telemt_geoip_city_mirrors()
        self.assertEqual(len(urls), 5)
        self.assertEqual(TELEMT_GEOIP_MIRRORS_COUNT, 5)

    def test_asn_mirrors_count(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_asn_mirrors
        urls = get_telemt_geoip_asn_mirrors()
        self.assertEqual(len(urls), 5)

    def test_all_urls_are_https(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_city_mirrors
        for url in get_telemt_geoip_city_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_city_urls_contain_dbip(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_city_mirrors
        for url in get_telemt_geoip_city_mirrors():
            self.assertIn("dbip-city-lite", url)
            self.assertIn("dbip-city-lite.mmdb.gz", url)

    def test_maxmind_urls_contain_geolite2(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_city_mirrors
        for url in get_telemt_geoip_city_mirrors(use_maxmind=True):
            self.assertIn("geolite2-city", url)
            self.assertIn("GeoLite2-City.mmdb.gz", url)

    def test_asn_urls_contain_geolite2_asn(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_asn_mirrors
        for url in get_telemt_geoip_asn_mirrors():
            self.assertIn("geolite2-asn", url)
            self.assertIn("GeoLite2-ASN.mmdb.gz", url)

    def test_has_jsdelivr_cdn(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_city_mirrors
        urls = get_telemt_geoip_city_mirrors()
        self.assertTrue(any("jsdelivr.net" in u for u in urls))

    def test_has_unpkg_cdn(self):
        from vless_installer.modules.telemt_geoip_mirrors import get_telemt_geoip_city_mirrors
        urls = get_telemt_geoip_city_mirrors()
        self.assertTrue(any("unpkg.com" in u for u in urls))


class TestTelemtGeoipSpecSanity(unittest.TestCase):
    """Sanity-проверки TELEMT_GEOIP_*_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_city_spec_name(self):
        from vless_installer.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_SPEC
        self.assertEqual(TELEMT_GEOIP_CITY_SPEC.name, "Telemt GeoIP City (DB-IP)")

    def test_city_maxmind_spec_name(self):
        from vless_installer.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_MAXMIND_SPEC
        self.assertEqual(TELEMT_GEOIP_CITY_MAXMIND_SPEC.name, "Telemt GeoIP City (MaxMind)")

    def test_asn_spec_name(self):
        from vless_installer.modules.telemt_geoip_packages import TELEMT_GEOIP_ASN_SPEC
        self.assertEqual(TELEMT_GEOIP_ASN_SPEC.name, "Telemt GeoIP ASN")

    def test_all_specs_manual_dir_is_root(self):
        from vless_installer.modules.telemt_geoip_packages import (
            TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC, TELEMT_GEOIP_ASN_SPEC,
        )
        for spec in (TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC, TELEMT_GEOIP_ASN_SPEC):
            self.assertEqual(spec.manual_incoming_dir, Path("/root"))

    def test_all_specs_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.telemt_geoip_packages import (
            TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC, TELEMT_GEOIP_ASN_SPEC,
        )
        for spec in (TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC, TELEMT_GEOIP_ASN_SPEC):
            for dest in spec.install_dests:
                self.assertNotEqual(spec.manual_incoming_dir, dest)

    def test_all_specs_post_install_set(self):
        from vless_installer.modules.telemt_geoip_packages import (
            TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC, TELEMT_GEOIP_ASN_SPEC,
        )
        for spec in (TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC, TELEMT_GEOIP_ASN_SPEC):
            self.assertIsNotNone(spec.post_install)


class TestTelemtGeoipPostInstall(unittest.TestCase):
    """post_install для TELEMT_GEOIP — gzip-decompress."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_non_gzip(self):
        from vless_installer.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_SPEC
        src = self._tmpdir / "fake.mmdb.gz"
        src.write_bytes(b"not a gzip" * 100)
        ok = TELEMT_GEOIP_CITY_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_returns_false_on_empty_file(self):
        from vless_installer.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_SPEC
        src = self._tmpdir / "empty.mmdb.gz"
        src.write_bytes(b"")
        ok = TELEMT_GEOIP_CITY_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_returns_false_on_small_gzip(self):
        """gzip распаковался, но результат < 1024 байт — отказ."""
        import gzip as _gzip
        from vless_installer.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_SPEC
        src = self._tmpdir / "small.mmdb.gz"
        with _gzip.open(src, "wb") as f:
            f.write(b"x" * 100)  # < 1024
        ok = TELEMT_GEOIP_CITY_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)


# ============================================================================
#  iperf3_mirrors
# ============================================================================
class TestIperf3Mirrors(unittest.TestCase):
    """iperf3_mirrors — зеркала для iperf3 static binary."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_non_empty_urls(self):
        from vless_installer.modules.iperf3_mirrors import get_iperf3_mirrors
        urls = get_iperf3_mirrors(arch="amd64")
        self.assertGreater(len(urls), 0)

    def test_all_urls_are_https(self):
        from vless_installer.modules.iperf3_mirrors import get_iperf3_mirrors
        for url in get_iperf3_mirrors(arch="amd64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_urls_contain_repo_and_filename(self):
        from vless_installer.modules.iperf3_mirrors import get_iperf3_mirrors
        for url in get_iperf3_mirrors(arch="amd64"):
            self.assertIn("userdocs", url)
            self.assertIn("iperf3-static", url)
            self.assertIn("iperf3-amd64", url)

    def test_arm64_arch(self):
        from vless_installer.modules.iperf3_mirrors import get_iperf3_mirrors
        for url in get_iperf3_mirrors(arch="arm64"):
            self.assertIn("iperf3-arm64", url)


class TestIperf3SpecSanity(unittest.TestCase):
    """Sanity-проверки IPERF3_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_iperf3_static(self):
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        self.assertEqual(IPERF3_SPEC.name, "iperf3 static")

    def test_filename_builder_uses_arch(self):
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        self.assertEqual(IPERF3_SPEC.filename_builder(arch="amd64"), "iperf3-amd64")
        self.assertEqual(IPERF3_SPEC.filename_builder(arch="arm64"), "iperf3-arm64")

    def test_install_dests_is_tmp(self):
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        self.assertEqual(IPERF3_SPEC.install_dests, [Path("/tmp")])

    def test_manual_dir_is_root(self):
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        self.assertEqual(IPERF3_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        for dest in IPERF3_SPEC.install_dests:
            self.assertNotEqual(IPERF3_SPEC.manual_incoming_dir, dest)

    def test_post_install_is_set(self):
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        self.assertIsNotNone(IPERF3_SPEC.post_install)

    def test_post_install_rejects_non_elf(self):
        import tempfile
        from vless_installer.modules.iperf3_packages import IPERF3_SPEC
        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "not-elf"
            src.write_bytes(b"<html>404</html>" * 100)
            ok = IPERF3_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
