#!/usr/bin/env python3
"""
tests/test_all_specs_real_fetch_package.py
───────────────────────────────────────────────────────────────────────────────
ОБЯЗАТЕЛЬНЫЕ regression-тесты для КАЖДОГО PackageSpec в проекте.

Эти тесты вызывают НАСТОЯЩИЙ fetch_package(SPEC, dry_run=True, **real_kwargs)
— НЕ замоканный — с теми же kwargs, что использует настоящий call site в
боевом коде. dry_run=True гарантированно возвращает False и не лезет в сеть,
но при этом ВЫПОЛНЯЕТ spec.filename_builder(**filename_kwargs) и
spec.mirror_urls_builder(filename=..., **filename_kwargs) — то есть ловит
TypeError/AttributeError при рассинхроне сигнатур.

Почему это нужно:
  Раньше все тесты мокали fetch_package целиком:
    patch("...fetch_package", side_effect=...)
  Реальная spec.filename_builder(**filename_kwargs) НЕ выполнялась НИ РАЗУ.
  Это позволило 4 багам (TypeError в filename_builder) пройти в продакшен:
    - TURNABLE_SPEC: lambda без параметров, call site передаёт version=
    - XRAY_ZIP_SPEC: lambda только arch, call site передаёт tag= и arch=
    - chk_spec: lambda без параметров, call site передаёт tag=
    - FPTN_SPEC: lambda filename, call site передаёт tag= И filename=
      (плюс conflict с mirror_urls_builder который тоже получает filename=)

  Этот тест-файл вызывает fetch_package с dry_run=True для КАЖДОГО spec
  с РЕАЛЬНЫМИ kwargs с call site — единственный способ поймать такие баги.

Если тест падает с TypeError — это означает что filename_builder или
mirror_urls_builder не принимает какие-то kwargs, которые реально
передаются на call site. Это КРИТИЧЕСКИЙ баг (крашит установку в проде).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


from chimera.modules.download_manager import fetch_package


# ============================================================================
#  Тест-класс для КАЖДОГО spec — реальный (НЕ замоканный) fetch_package вызов
# ============================================================================
class TestAllSpecsRealFetchPackageCall(unittest.TestCase):
    """Для каждого spec'а вызываем НАСТОЯЩИЙ fetch_package(dry_run=True)
    с РЕАЛЬНЫМИ kwargs с call site. dry_run=True не лезет в сеть, но
    выполняет filename_builder и mirror_urls_builder — ловит TypeError.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    # ── Wave 1: turntunnel, turnable ──────────────────────────────────────

    def test_turntunnel_spec_real_call(self):
        """TURNTUNNEL_SPEC — call site: fetch_package(TURNTUNNEL_SPEC)."""
        from chimera.modules.turn_packages import TURNTUNNEL_SPEC
        # dry_run=True → не лезет в сеть, только проверяет сигнатуры
        result = fetch_package(TURNTUNNEL_SPEC, dry_run=True)
        self.assertFalse(result)  # dry_run всегда False

    def test_turnable_spec_real_call(self):
        """TURNABLE_SPEC — call site: fetch_package(TURNABLE_SPEC, version=_TURNABLE_VERSION).

        БАГ №1 (исправлен): filename_builder был lambda: без параметров,
        call site передавал version='0.4.1' → TypeError → краш установки.
        """
        from chimera.modules.turn_packages import TURNABLE_SPEC
        result = fetch_package(TURNABLE_SPEC, dry_run=True, version="0.4.1")
        self.assertFalse(result)

    # ── Wave 2: wdtt, webdav_tunnel, go_toolchain ─────────────────────────

    def test_wdtt_source_spec_real_call(self):
        """WDTT_SOURCE_SPEC — call site: fetch_package(WDTT_SOURCE_SPEC)."""
        from chimera.modules.wdtt_packages import WDTT_SOURCE_SPEC
        result = fetch_package(WDTT_SOURCE_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_webdav_source_spec_real_call(self):
        """WEBDAV_SOURCE_SPEC — call site: fetch_package(WEBDAV_SOURCE_SPEC)."""
        from chimera.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        result = fetch_package(WEBDAV_SOURCE_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_go_toolchain_spec_real_call(self):
        """GO_TOOLCHAIN_SPEC — call site: fetch_package(GO_TOOLCHAIN_SPEC, version=..., arch=...)."""
        from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        result = fetch_package(GO_TOOLCHAIN_SPEC, dry_run=True,
                               version="go1.23.4", arch="amd64")
        self.assertFalse(result)

    # ── Wave 3: hysteria2, dnscrypt ───────────────────────────────────────

    def test_hysteria2_spec_real_call(self):
        """HYSTERIA2_SPEC — call site: fetch_package(HYSTERIA2_SPEC, arch=...)."""
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        result = fetch_package(HYSTERIA2_SPEC, dry_run=True, arch="amd64")
        self.assertFalse(result)

    def test_dnscrypt_spec_real_call(self):
        """DNSCRYPT_SPEC — call site: fetch_package(DNSCRYPT_SPEC, tag=..., arch=...)."""
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        result = fetch_package(DNSCRYPT_SPEC, dry_run=True,
                               tag="2.1.5", arch="linux_x86_64")
        self.assertFalse(result)

    # ── Wave 4: xray, naiveproxy, fptn ────────────────────────────────────

    def test_xray_zip_spec_real_call(self):
        """XRAY_ZIP_SPEC — call site: fetch_package(XRAY_ZIP_SPEC, tag=..., arch=...).

        БАГ №1 (исправлен): filename_builder был lambda arch: (только arch),
        call site передавал tag= и arch= → TypeError → автоустановка Xray
        ВСЕГДА проваливалась со всех 14 зеркал.
        """
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        result = fetch_package(XRAY_ZIP_SPEC, dry_run=True,
                               tag="v25.4.30", arch="64")
        self.assertFalse(result)

    def test_xray_checksums_spec_real_call(self):
        """XRAY_CHECKSUMS_SPEC — может вызываться с tag= и arch=."""
        from chimera.modules.xray_packages import XRAY_CHECKSUMS_SPEC
        result = fetch_package(XRAY_CHECKSUMS_SPEC, dry_run=True,
                              tag="v25.4.30", arch="64")
        self.assertFalse(result)

    def test_xray_installer_spec_real_call(self):
        """XRAY_INSTALLER_SPEC — call site: fetch_package(XRAY_INSTALLER_SPEC)."""
        from chimera.modules.xray_packages import XRAY_INSTALLER_SPEC
        result = fetch_package(XRAY_INSTALLER_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_xray_chk_spec_internal_real_call(self):
        """Внутренний chk_spec в _fetch_dgst_content — вызывается с tag= и arch=.

        БАГ №1 (исправлен): filename_builder был lambda: без параметров,
        call site передавал tag= → TypeError → SHA256 верификация
        молча отключена на 100% установок Xray.
        """
        from chimera.modules.xray_packages import _fetch_dgst_content
        # dry_run не подходит для _fetch_dgst_content (она сама зовёт
        # fetch_package без dry_run). Мокаем urlopen чтобы не лезть в сеть.
        from unittest.mock import MagicMock
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   return_value=mock_resp):
            # Это НЕ должно крашить с TypeError. Вернёт None (сеть "недоступна").
            result = _fetch_dgst_content("v25.4.30", "64")
        # None — OK (сеть мокнута на пустой ответ). TypeError — FAIL.
        self.assertIsNone(result)

    def test_naiveproxy_spec_real_call(self):
        """NAIVEPROXY_SPEC — call site: fetch_package(NAIVEPROXY_SPEC)."""
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        result = fetch_package(NAIVEPROXY_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_fptn_spec_real_call(self):
        """FPTN_SPEC — call site: fetch_package(FPTN_SPEC, tag=..., deb_filename=...).

        БАГ №1 (исправлен): filename_builder был lambda filename: (только filename),
        call site передавал tag= И filename= → TypeError → краш установки fptn.

        БАГ №1b (найден при фиксе): mirror_urls_builder получал filename=
        дважды (от download_manager И от caller) → TypeError. Решение:
        переименовать caller kwarg с filename на deb_filename.
        """
        from chimera.modules.fptn_packages import FPTN_SPEC
        result = fetch_package(FPTN_SPEC, dry_run=True,
                               tag="0.7.6",
                               deb_filename="fptn-server-ubuntu22.04-amd64.deb")
        self.assertFalse(result)

    # ── Wave 5: awg_cascade, slipgate, telemt_panel, network_bench ────────

    def test_ru_zone_spec_real_call(self):
        """RU_ZONE_SPEC — call site: fetch_package(RU_ZONE_SPEC)."""
        from chimera.modules.awg_cascade_packages import RU_ZONE_SPEC
        result = fetch_package(RU_ZONE_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_slipgate_installer_spec_real_call(self):
        """SLIPGATE_INSTALLER_SPEC — call site: fetch_package(SLIPGATE_INSTALLER_SPEC)."""
        from chimera.modules.slipgate_packages import SLIPGATE_INSTALLER_SPEC
        result = fetch_package(SLIPGATE_INSTALLER_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_telemt_geoip_city_spec_real_call(self):
        """TELEMT_GEOIP_CITY_SPEC — call site: fetch_package(TELEMT_GEOIP_CITY_SPEC)."""
        from chimera.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_SPEC
        result = fetch_package(TELEMT_GEOIP_CITY_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_telemt_geoip_city_maxmind_spec_real_call(self):
        """TELEMT_GEOIP_CITY_MAXMIND_SPEC — call site: fetch_package(TELEMT_GEOIP_CITY_MAXMIND_SPEC)."""
        from chimera.modules.telemt_geoip_packages import TELEMT_GEOIP_CITY_MAXMIND_SPEC
        result = fetch_package(TELEMT_GEOIP_CITY_MAXMIND_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_telemt_geoip_asn_spec_real_call(self):
        """TELEMT_GEOIP_ASN_SPEC — call site: fetch_package(TELEMT_GEOIP_ASN_SPEC)."""
        from chimera.modules.telemt_geoip_packages import TELEMT_GEOIP_ASN_SPEC
        result = fetch_package(TELEMT_GEOIP_ASN_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_iperf3_spec_real_call(self):
        """IPERF3_SPEC — call site: fetch_package(IPERF3_SPEC, arch=...)."""
        from chimera.modules.iperf3_packages import IPERF3_SPEC
        result = fetch_package(IPERF3_SPEC, dry_run=True, arch="amd64")
        self.assertFalse(result)

    # ── Wave 6: awg_transport, olcrtc ─────────────────────────────────────

    def test_awg_tools_spec_real_call(self):
        """AWG_TOOLS_SPEC — call site: fetch_package(AWG_TOOLS_SPEC, tag=..., arch=...)."""
        from chimera.modules.awg_transport_packages import AWG_TOOLS_SPEC
        result = fetch_package(AWG_TOOLS_SPEC, dry_run=True,
                               tag="v1.0.0", arch="amd64")
        self.assertFalse(result)

    def test_awg_go_source_spec_real_call(self):
        """AWG_GO_SOURCE_SPEC — call site: fetch_package(AWG_GO_SOURCE_SPEC)."""
        from chimera.modules.awg_transport_packages import AWG_GO_SOURCE_SPEC
        result = fetch_package(AWG_GO_SOURCE_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_awg_kmod_source_spec_real_call(self):
        """AWG_KMOD_SOURCE_SPEC — call site: fetch_package(AWG_KMOD_SOURCE_SPEC)."""
        from chimera.modules.awg_transport_packages import AWG_KMOD_SOURCE_SPEC
        result = fetch_package(AWG_KMOD_SOURCE_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_olcrtc_source_spec_real_call(self):
        """OLCRTC_SOURCE_SPEC — call site: fetch_package(OLCRTC_SOURCE_SPEC)."""
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        result = fetch_package(OLCRTC_SOURCE_SPEC, dry_run=True)
        self.assertFalse(result)

    # ── Pre-existing (уже мигрированы до Wave 1): mieru, telemt, geo ──────

    def test_mita_deb_spec_real_call(self):
        """MITA_DEB_SPEC — call site: fetch_package(MITA_DEB_SPEC, version=..., arch=...)."""
        from chimera.modules.mieru_packages import MITA_DEB_SPEC
        result = fetch_package(MITA_DEB_SPEC, dry_run=True,
                               version="3.33.0", arch="amd64")
        self.assertFalse(result)

    def test_mita_rpm_spec_real_call(self):
        """MITA_RPM_SPEC — call site: fetch_package(MITA_RPM_SPEC, version=..., rpm_arch=...)."""
        from chimera.modules.mieru_packages import MITA_RPM_SPEC
        result = fetch_package(MITA_RPM_SPEC, dry_run=True,
                               version="3.33.0", rpm_arch="x86_64")
        self.assertFalse(result)

    def test_mita_targz_spec_real_call(self):
        """MITA_TARGZ_SPEC — call site: fetch_package(MITA_TARGZ_SPEC, version=..., arch=...)."""
        from chimera.modules.mieru_packages import MITA_TARGZ_SPEC
        result = fetch_package(MITA_TARGZ_SPEC, dry_run=True,
                               version="3.33.0", arch="amd64")
        self.assertFalse(result)

    def test_mieru_targz_spec_real_call(self):
        """MIERU_TARGZ_SPEC — call site: fetch_package(MIERU_TARGZ_SPEC, version=..., arch=...)."""
        from chimera.modules.mieru_packages import MIERU_TARGZ_SPEC
        result = fetch_package(MIERU_TARGZ_SPEC, dry_run=True,
                               version="3.33.0", arch="amd64")
        self.assertFalse(result)

    def test_geosite_spec_real_call(self):
        """GEOSITE_SPEC — call site: fetch_package(GEOSITE_SPEC)."""
        from chimera.modules.geo_packages import GEOSITE_SPEC
        result = fetch_package(GEOSITE_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_geoip_spec_real_call(self):
        """GEOIP_SPEC — call site: fetch_package(GEOIP_SPEC)."""
        from chimera.modules.geo_packages import GEOIP_SPEC
        result = fetch_package(GEOIP_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_telemt_spec_real_call(self):
        """TELEMT_SPEC — call site: fetch_package(TELEMT_SPEC)."""
        from chimera.modules.telemt_packages import TELEMT_SPEC
        result = fetch_package(TELEMT_SPEC, dry_run=True)
        self.assertFalse(result)

    def test_telemt_panel_spec_real_call(self):
        """TELEMT_PANEL_SPEC — call site: fetch_package(TELEMT_PANEL_SPEC)."""
        from chimera.modules.telemt_packages import TELEMT_PANEL_SPEC
        result = fetch_package(TELEMT_PANEL_SPEC, dry_run=True)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
