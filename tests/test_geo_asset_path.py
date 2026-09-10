#!/usr/bin/env python3
"""
tests/test_geo_asset_path.py
───────────────────────────────────────────────────────────────────────────────
: регрессионные тесты гео-активов Xray.

ИНЦИДЕНТ («в каскадном режиме не работает НИЧЕГО, i/o timeout»):
  • Xray-core ищет geoip/geosite ТОЛЬКО в: env xray.location.asset →
    каталог бинарника → /usr/local/share/xray → /usr/share/xray →
    /opt/share/xray (исходник: common/platform/others.go, GetAssetLocation).
    /etc/xray в списке ОТСУТСТВУЕТ.
  • Поле routing.geoDataBasePath Xray-core НЕ поддерживает — молча игнорирует.
  • Конфиг с geosite:category-ru + geoip:ru (их генерирует ТОЛЬКО раздельное
    туннелирование / РФ-подсети) при отсутствии файлов в пути поиска →
    xray exit 23 → RestartPreventExitStatus=23 → служба МЁРТВА → порт 443
    закрыт → i/o timeout для ВСЕХ клиентов. Режим A без split не содержит
    geo-правил — потому «Режим A работает, Режим B нет».

Фиксы 
  1. create_xray_service: Environment=xray.location.asset=/etc/xray
     (когда оба .dat в /etc/xray и >1 МБ).
  2. _geo_files_available: зеркалирование в /usr/local/share/xray
     (_mirror_geo_to_share_dir).
  3. strip_geo_rules + self-heal в 4 генераторах: провал `xray run -test`
     → geo-правила удаляются → ретест → живой конфиг вместо мёртвого сервера.
"""
from __future__ import annotations

import sys
import tempfile
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


_setup_core_in_sysmodules()


# ═════════════════════════════════════════════════════════════════════════════
#  1. Порядок поиска geo-файлов: константы соответствуют исходникам Xray-core
# ═════════════════════════════════════════════════════════════════════════════
class TestXrayRealAssetDirs(unittest.TestCase):
    def test_share_dir_first_in_real_dirs(self):
        from chimera.modules.split_tunnel import XRAY_REAL_ASSET_DIRS
        self.assertEqual(XRAY_REAL_ASSET_DIRS[0], Path("/usr/local/share/xray"))
        self.assertIn(Path("/usr/share/xray"), XRAY_REAL_ASSET_DIRS)

    def test_etc_xray_not_in_xray_search(self):
        """Документация факта: /etc/xray НЕ в пути поиска Xray-core
        (поэтому нужен env-пин + зеркалирование)."""
        from chimera.modules.split_tunnel import XRAY_REAL_ASSET_DIRS
        self.assertNotIn(Path("/etc/xray"), XRAY_REAL_ASSET_DIRS)


# ═════════════════════════════════════════════════════════════════════════════
#  2. Зеркалирование в /usr/local/share/xray
# ═════════════════════════════════════════════════════════════════════════════
class TestMirrorGeoToShareDir(unittest.TestCase):
    def setUp(self):
        import shutil
        self._tmp = Path(tempfile.mkdtemp())
        self._etc = self._tmp / "etc_xray"; self._etc.mkdir()
        self._share = self._tmp / "share_xray"
        # гео-исходники (разного размера — имитация runetfreedom)
        (self._etc / "geosite.dat").write_bytes(b"G" * 73000000)
        (self._etc / "geoip.dat").write_bytes(b"I" * 17000000)
        self._saved = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _patch_dirs(self):
        from chimera.modules import split_tunnel as st
        return patch.object(st, "XRAY_REAL_ASSET_DIRS",
                            [self._share, self._tmp / "usr_share",
                             self._tmp / "opt_share"])

    def test_mirrors_files_to_share_dir(self):
        from chimera.modules import split_tunnel as st
        with self._patch_dirs():
            mirrored = st._mirror_geo_to_share_dir(
                self._etc / "geosite.dat", self._etc / "geoip.dat")
        self.assertTrue(mirrored)
        self.assertTrue((self._share / "geosite.dat").exists())
        self.assertEqual((self._share / "geosite.dat").stat().st_size,
                         73000000)
        self.assertTrue((self._share / "geoip.dat").exists())

    def test_no_copy_when_identical(self):
        from chimera.modules import split_tunnel as st
        with self._patch_dirs():
            st._mirror_geo_to_share_dir(
                self._etc / "geosite.dat", self._etc / "geoip.dat")
            mirrored2 = st._mirror_geo_to_share_dir(
                self._etc / "geosite.dat", self._etc / "geoip.dat")
        self.assertFalse(mirrored2)  # идентичные — перезаписи нет

    def test_overwrites_stale_stock(self):
        """Стоковый geosite (5 МБ из zip XTLS) замещается runetfreedom."""
        from chimera.modules import split_tunnel as st
        self._share.mkdir(parents=True, exist_ok=True)
        (self._share / "geosite.dat").write_bytes(b"S" * 5000000)  # сток
        with self._patch_dirs():
            st._mirror_geo_to_share_dir(
                self._etc / "geosite.dat", self._etc / "geoip.dat")
        self.assertEqual((self._share / "geosite.dat").stat().st_size,
                         73000000)  # заменён на runetfreedom


# ═════════════════════════════════════════════════════════════════════════════
#  3. strip_geo_rules — хирургическое удаление geo-правил
# ═════════════════════════════════════════════════════════════════════════════
class TestStripGeoRules(unittest.TestCase):
    def _cfg(self):
        return {
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "geoDataBasePath": "/etc/xray",
                "rules": [
                    {"type": "field", "inboundTag": ["xray-stats-api"],
                     "outboundTag": "xray-stats-api"},
                    {"type": "field", "domain": ["domain:2ip.ru",
                     "geosite:category-ru", "geosite:ru-available-only-inside"],
                     "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:ru"],
                     "outboundTag": "direct"},
                    {"type": "field", "ip": ["127.0.0.1/8", "::1/128"],
                     "outboundTag": "direct"},
                    {"type": "field", "protocol": ["bittorrent"],
                     "outboundTag": "BLOCK"},
                    {"type": "field", "network": "tcp",
                     "outboundTag": "chain-exit-1"},
                ],
            }
        }

    def test_strips_only_geo_rules(self):
        from chimera.modules.split_tunnel import strip_geo_rules
        cfg = self._cfg()
        changed = strip_geo_rules(cfg)
        self.assertTrue(changed)
        rules = cfg["routing"]["rules"]
        tags = [r.get("outboundTag") for r in rules]
        # geo-правила удалены
        self.assertEqual(tags.count("direct"), 1)  # остался только loopback
        # остальные правила целы
        self.assertIn("xray-stats-api", tags)
        self.assertIn("BLOCK", tags)
        self.assertIn("chain-exit-1", tags)
        self.assertEqual(len(rules), 4)

    def test_removes_geoDataBasePath(self):
        from chimera.modules.split_tunnel import strip_geo_rules
        cfg = self._cfg()
        strip_geo_rules(cfg)
        self.assertNotIn("geoDataBasePath", cfg["routing"])

    def test_no_geo_rules_no_change(self):
        from chimera.modules.split_tunnel import strip_geo_rules
        cfg = {"routing": {"rules": [
            {"type": "field", "network": "tcp", "outboundTag": "direct"}]}}
        self.assertFalse(strip_geo_rules(cfg))

    def test_catchall_survives(self):
        """catch-all (network tcp→chain-exit-1) обязан выжить — иначе
        не-РФ трафик без маршрута = EOF у клиентов."""
        from chimera.modules.split_tunnel import strip_geo_rules
        cfg = self._cfg()
        strip_geo_rules(cfg)
        self.assertTrue(any(r.get("network") == "tcp"
                            and r.get("outboundTag") == "chain-exit-1"
                            for r in cfg["routing"]["rules"]))


# ═════════════════════════════════════════════════════════════════════════════
#  4. Юнит-файл: Environment=xray.location.asset
# ═════════════════════════════════════════════════════════════════════════════
class TestUnitEnvPin(unittest.TestCase):
    def test_unit_template_contains_env_placeholder(self):
        """Шаблон юнита содержит подстановку {_geo_env_line} в [Service]."""
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "xray_install.py").read_text()
        self.assertIn("{_geo_env_line}", src)
        # и она подставляется в [Service] (после Group=xray)
        self.assertLess(
            src.index("Group=xray\n        {_geo_env_line}"),
            src.index("CapabilityBoundingSet"))

    def test_self_heal_in_all_generators(self):
        """Все 4 генератора конфигов содержат geo-self-heal."""
        for fname, marker in (
            ("xray_install.py", "strip_geo_rules"),
            ("chain_nodes.py", "strip_geo_rules"),
        ):
            src = (_PROJECT_ROOT / "chimera" / "modules" / fname).read_text()
            self.assertIn(marker, src,
                          f"{fname} должен содержать geo-self-heal")
        xi = (_PROJECT_ROOT / "chimera" / "modules" /
              "xray_install.py").read_text()
        cn = (_PROJECT_ROOT / "chimera" / "modules" /
              "chain_nodes.py").read_text()
        self.assertGreaterEqual(xi.count("GEO-SELF-HEAL"), 2)   # A + xhttp
        self.assertGreaterEqual(cn.count("GEO-SELF-HEAL"), 2)   # B + B-multi


# ═════════════════════════════════════════════════════════════════════════════
#  5. Интеграция self-heal в генератор (поведенческий тест)
# ═════════════════════════════════════════════════════════════════════════════
class TestGeneratorSelfHealBehavior(unittest.TestCase):
    """Провал валидации → geo-правила удалены → конфиг перезаписан →
    ретест успешен → предупреждающее сообщение."""

    def test_heal_flow(self):
        import json as _json
        from chimera.modules import split_tunnel as st

        _calls = {"n": 0}

        def fake_run(cmd, **kw):
            class _R:
                def __init__(self, rc):
                    self.returncode = rc
                    self.stdout = ""
                    self.stderr = "geodata: failed to open geosite.dat"
            rc = 23 if _calls["n"] == 0 else 0
            _calls["n"] += 1
            return _R(rc)

        cfg = {
            "routing": {
                "geoDataBasePath": "/etc/xray",
                "rules": [
                    {"type": "field", "domain": ["geosite:category-ru"],
                     "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:ru"],
                     "outboundTag": "direct"},
                    {"type": "field", "network": "tcp",
                     "outboundTag": "chain-exit-1"},
                ],
            }
        }
        # эмуляция потока self-heal из генератора
        r = fake_run([])
        healed = False
        try:
            if r.returncode != 0:
                _cfg_h = _json.loads(_json.dumps(cfg))  # копия
                if st.strip_geo_rules(_cfg_h):
                    # (в генераторе: запись + _set_config_owner + ретест)
                    r2 = fake_run([])
                    if r2.returncode == 0:
                        healed = True
                        cfg = _cfg_h
        except Exception:
            pass
        self.assertTrue(healed)
        self.assertEqual(len(cfg["routing"]["rules"]), 1)
        self.assertEqual(cfg["routing"]["rules"][0]["outboundTag"],
                         "chain-exit-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
