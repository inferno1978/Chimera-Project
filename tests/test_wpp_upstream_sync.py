#!/usr/bin/env python3
"""
tests/test_wpp_upstream_sync.py

Регрессия синхронизации WPP с апстримом POLESNIESOVETI12/web-panel-proxy
v2.4.3 (2026-10-14, upstream воскрес после удаления).

Проверяет, что 3-way merge не сломал ни chimera-твики, ни апстримные
изменения v2.4.3:
  • версии синхронизированы (wpp_ui.VERSION == wpp_packages.WPP_FRONT_VERSION)
  • chimera-твики живы (FINGERPRINTS, admin-блоки, chimera-пути)
  • апстримные фичи v2.4.3 живы (MAX/oneme, openflux_import_uri, mkstemp,
    _timestamp, multi-source геолокация, _action_lock)
  • mirror ladder: наш GitLab первичен, upstream codeload — второй
  • vendored tarball v2.4.3 лежит в репо
"""
import base64
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))

from chimera.modules import (  # noqa: E402
    wpp_components, wpp_metrics, wpp_mirrors, wpp_nodes,
    wpp_openflux, wpp_packages, wpp_panel_extras, wpp_panel_web, wpp_ui,
    wpp_update,
)


class TestVersionsInSync(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(wpp_ui.VERSION, "2.4.3")
        self.assertEqual(wpp_packages.WPP_FRONT_VERSION, "2.4.3")

    def test_vendored_tarball_present(self):
        tarball = ROOT / "vendor" / "wpp-front" / "web-panel-proxy-v2.4.3.tar.gz"
        self.assertTrue(tarball.exists(), f"missing {tarball}")
        self.assertGreater(tarball.stat().st_size, wpp_packages.WPP_TARBALL_MIN_SIZE)
        with tarball.open("rb") as fh:
            self.assertEqual(fh.read(2), b"\x1f\x8b")  # gzip magic


class TestChimeraTweaksSurvived(unittest.TestCase):
    """Наши модификации не должны пострадать при синхронизации."""

    def test_fingerprints_block(self):
        self.assertEqual(len(wpp_ui.FINGERPRINTS), 11)
        html = wpp_ui.fingerprint_options("chrome")
        self.assertIn("360", html)
        self.assertIn("randomized", html)

    def test_metrics_uses_chimera_paths(self):
        self.assertIn("/var/lib/xray-installer", str(wpp_metrics.STATE))
        self.assertTrue(hasattr(wpp_metrics, "collect_once"))
        # chimera-сервисы, а не web-panel-proxy-*
        self.assertIn("wpp-web.service", wpp_metrics.SERVICES.values())

    def test_components_uses_chimera_paths(self):
        src = inspect.getsource(wpp_components)
        self.assertIn("/var/lib/xray-installer/wpp-components", src)
        self.assertIn("xray.service", src)

    def test_panel_web_imports(self):
        # наш интеграционный слой тянет апстримную openflux_import_uri
        self.assertEqual(wpp_panel_web.openflux_import_uri, wpp_ui.openflux_import_uri)

    def test_awg_i2_i5_tweak_untouched(self):
        from chimera.modules import wpp_awg
        self.assertTrue(hasattr(wpp_awg, "_i_chain_field"))


class TestUpstream243Features(unittest.TestCase):
    """Апстримные изменения v2.4.3 обязаны присутствовать."""

    def test_openflux_import_uri_yandex(self):
        uri = wpp_ui.openflux_import_uri({
            "name": "Tab", "transport": "yandex",
            "url": "https://disk.yandex.ru/i/x",
            "key": "k" * 43, "platform": "android",
        })
        self.assertTrue(uri.startswith("openflux://import?data="))
        payload = json.loads(base64.urlsafe_b64decode(uri.split("data=")[1] + "==="))
        self.assertEqual(payload["doc_url"], "https://disk.yandex.ru/i/x")
        self.assertEqual(payload["encryption_key"], "k" * 43)
        self.assertEqual(payload["mtu"], 1400)

    def test_openflux_import_uri_max_oneme(self):
        uri = wpp_ui.openflux_import_uri({
            "name": "Max", "transport": "oneme", "url": "",
            "max_client_token": "ct", "max_uid": 42, "platform": "ios",
        })
        payload = json.loads(base64.urlsafe_b64decode(uri.split("data=")[1] + "==="))
        self.assertEqual(payload["max_token"], "ct")
        self.assertEqual(payload["max_uid"], 42)
        self.assertNotIn("encryption_key", payload)

    def test_openflux_oneme_transport(self):
        self.assertIn("oneme", wpp_openflux.TRANSPORTS)
        sig = inspect.signature(wpp_openflux.create_profile)
        for param in ("max_server_token", "max_client_token", "max_uid"):
            self.assertIn(param, sig.parameters)

    def test_metrics_atomic_json_mkstemp(self):
        src = inspect.getsource(wpp_metrics.atomic_json)
        self.assertIn("mkstemp", src)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state.json"
            wpp_metrics.atomic_json(target, {"x": 1})
            self.assertEqual(json.loads(target.read_text()), {"x": 1})
            # никаких остатков tmp-файлов
            self.assertEqual([p.name for p in target.parent.iterdir()], ["state.json"])

    def test_update_timestamp_helper(self):
        self.assertEqual(wpp_update._timestamp(None), 0)
        self.assertEqual(wpp_update._timestamp("17"), 17)
        self.assertEqual(wpp_update._timestamp(12.5), 12)

    def test_nodes_multisource_location_helpers(self):
        self.assertEqual(wpp_nodes._country_code(" ru "), "RU")
        self.assertEqual(wpp_nodes._country_code("RUS1"), "")
        self.assertEqual(wpp_nodes._optional_location_text(""), "")
        self.assertTrue(callable(wpp_nodes._location_json))

    def test_components_action_lock(self):
        src = inspect.getsource(wpp_components)
        self.assertIn("_action_lock", src)
        self.assertIn("fcntl", src)

    def test_panel_extras_dropped_unused_import(self):
        # v2.4.3 убрал неиспользуемый import base64
        src = inspect.getsource(wpp_panel_extras)
        self.assertNotIn("import base64", src)


class TestMirrorLadder(unittest.TestCase):
    def test_ladder_order(self):
        urls = wpp_mirrors.front_mirror_urls(
            "web-panel-proxy-v2.4.3.tar.gz", version="2.4.3")
        self.assertEqual(len(urls), 12)
        # 1) наш GitLab raw — первичный
        self.assertIn("gitlab.com/netwalker071778/chimera-project", urls[0])
        self.assertIn("web-panel-proxy-v2.4.3.tar.gz", urls[0])
        # 2) оживший апстрим codeload — канонический fallback
        self.assertEqual(
            urls[1],
            "https://codeload.github.com/POLESNIESOVETI12/web-panel-proxy"
            "/tar.gz/refs/tags/v2.4.3")
        # наш мёртвый GitHub (shadow-ban) после апстрима
        self.assertIn("raw.githubusercontent.com/inferno1978", urls[2])

    def test_version_file_urls_upstream_first(self):
        urls = wpp_mirrors.version_file_urls()
        self.assertEqual(
            urls[0],
            "https://api.github.com/repos/POLESNIESOVETI12/web-panel-proxy/releases/latest")


class TestPanelWebMaxFormFields(unittest.TestCase):
    """create_profile получает MAX-поля из формы (наш интеграционный слой)."""

    def test_create_call_passes_max_fields(self):
        src = inspect.getsource(wpp_panel_web)
        needle = 'form.get("max_server_token","")'
        self.assertIn(needle, src)
        self.assertIn('form.get("max_client_token","")', src)
        self.assertIn('form.get("max_uid","")', src)

    def test_openflux_qr_uses_import_uri(self):
        src = inspect.getsource(wpp_panel_web)
        self.assertIn("qr_png_bytes(openflux_import_uri(profile))", src)


if __name__ == "__main__":
    unittest.main()
