#!/usr/bin/env python3
"""
tests/test_routing_rules.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/routing_rules.py.

Покрывает:
  1. Валидаторы (имя, домены, ip/cidr, порты, приоритет)
  2. _rr_load / _rr_save — JSON I/O (0600)
  3. _rr_build_xray_rules — сборка Xray-правил, разбивка >500 по чанкам,
     AND-семантика полей, отказ при разбивке+доменах
  4. _rr_apply_to_xray — вставка top / before_catchall, удаление старых
     custom:*, порядок по priority, оба конфига, откат при невалидном
     конфиге (xray run -test)
  5. restore_routing_rules_if_needed — re-apply после regenerate
  6. _rr_is_catchall — определение catch-all
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules
    (канон test_youtube_route.py — exec ПРЯМО в __dict__ фейкового модуля)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    fake_core = types.ModuleType("chimera._core")
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _make_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


def _make_xray_config(routing_rules: list = None,
                      outbounds: list = None) -> dict:
    if outbounds is None:
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ]
    return {
        "inbounds": [{"protocol": "vless", "tag": "vless-in", "port": 443,
                      "settings": {"clients": []}}],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules if routing_rules is not None else [
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Валидаторы
# ══════════════════════════════════════════════════════════════════════════════

class TestValidators(unittest.TestCase):
    """Валидаторы полей."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_valid(self):
        from chimera.modules.routing_rules import _rr_validate_name
        self.assertIsNone(_rr_validate_name("ru-subnets-via-exit2"))
        self.assertIsNone(_rr_validate_name("a.b-c_1"))
        self.assertIsNone(_rr_validate_name("AbC"))  # → lower в apply-flow

    def test_name_invalid(self):
        from chimera.modules.routing_rules import _rr_validate_name
        self.assertIsNotNone(_rr_validate_name(""))
        self.assertIsNotNone(_rr_validate_name("-abc"))    # начинается с -
        self.assertIsNotNone(_rr_validate_name("a"))
        self.assertIsNotNone(_rr_validate_name("a b"))
        self.assertIsNotNone(_rr_validate_name("a" * 65))
        self.assertIsNotNone(_rr_validate_name("кириллица"))

    def test_domain_items(self):
        from chimera.modules.routing_rules import _rr_validate_domain_item
        self.assertIsNone(_rr_validate_domain_item("example.com"))
        self.assertIsNone(_rr_validate_domain_item("domain:google.com"))
        self.assertIsNone(_rr_validate_domain_item("full:exact.example.com"))
        self.assertIsNone(_rr_validate_domain_item("geosite:category-ads-all"))
        self.assertIsNone(_rr_validate_domain_item("regexp:.*\\.ru$"))
        self.assertIsNotNone(_rr_validate_domain_item("nodot"))
        self.assertIsNotNone(_rr_validate_domain_item("with space.com"))
        self.assertIsNotNone(_rr_validate_domain_item("domain:"))
        self.assertIsNotNone(_rr_validate_domain_item("bad!chars.com"))

    def test_ip_items(self):
        from chimera.modules.routing_rules import _rr_validate_ip_item
        self.assertIsNone(_rr_validate_ip_item("1.2.3.4"))
        self.assertIsNone(_rr_validate_ip_item("1.2.3.0/24"))
        self.assertIsNone(_rr_validate_ip_item("2001:db8::/32"))
        self.assertIsNone(_rr_validate_ip_item("geoip:ru"))
        self.assertIsNotNone(_rr_validate_ip_item("1.2.3.256"))
        self.assertIsNotNone(_rr_validate_ip_item("1.2.3.0/40"))
        self.assertIsNotNone(_rr_validate_ip_item("geoip:"))
        self.assertIsNotNone(_rr_validate_ip_item("just-a-word"))

    def test_port_items(self):
        from chimera.modules.routing_rules import _rr_validate_port_item
        self.assertIsNone(_rr_validate_port_item("443"))
        self.assertIsNone(_rr_validate_port_item("1000-2000"))
        self.assertIsNotNone(_rr_validate_port_item("0"))
        self.assertIsNotNone(_rr_validate_port_item("65536"))
        self.assertIsNotNone(_rr_validate_port_item("2000-1000"))
        self.assertIsNotNone(_rr_validate_port_item("443;80"))

    def test_priority(self):
        from chimera.modules.routing_rules import _rr_validate_priority
        self.assertIsNone(_rr_validate_priority("10"))
        self.assertIsNone(_rr_validate_priority("0"))
        self.assertIsNotNone(_rr_validate_priority(""))
        self.assertIsNotNone(_rr_validate_priority("-5"))
        self.assertIsNotNone(_rr_validate_priority("abc"))
        self.assertIsNotNone(_rr_validate_priority("10000"))

    def test_list_validators_allow_empty(self):
        from chimera.modules.routing_rules import (
            _rr_validate_domains, _rr_validate_ips, _rr_validate_ports,
        )
        self.assertIsNone(_rr_validate_domains(""))
        self.assertIsNone(_rr_validate_domains("example.com, domain:x.com"))
        self.assertIsNotNone(_rr_validate_domains("example.com, bad one"))
        self.assertIsNone(_rr_validate_ips(""))
        self.assertIsNotNone(_rr_validate_ips("1.2.3.4, 999.1.1.1"))
        self.assertIsNone(_rr_validate_ports(""))
        self.assertIsNotNone(_rr_validate_ports("80, 99999"))


# ══════════════════════════════════════════════════════════════════════════════
#  State I/O
# ══════════════════════════════════════════════════════════════════════════════

class TestLoadSave(unittest.TestCase):
    """_rr_load / _rr_save."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "routing_rules.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _p(self):
        return patch("chimera.modules.routing_rules.RR_STATE_FILE", self._state)

    def test_load_defaults_when_no_file(self):
        from chimera.modules.routing_rules import _rr_load
        with self._p():
            self.assertEqual(_rr_load(), {"version": 1, "rules": []})

    def test_load_defaults_on_corrupt(self):
        from chimera.modules.routing_rules import _rr_load
        self._state.write_text("{invalid")
        with self._p():
            self.assertEqual(_rr_load(), {"version": 1, "rules": []})

    def test_save_then_load(self):
        from chimera.modules.routing_rules import _rr_load, _rr_save
        data = {"version": 1, "rules": [{"name": "x", "enabled": True}]}
        with self._p():
            _rr_save(data)
            loaded = _rr_load()
        self.assertEqual(loaded["rules"][0]["name"], "x")

    def test_save_sets_chmod_600(self):
        import stat, os
        from chimera.modules.routing_rules import _rr_save
        with self._p():
            _rr_save({"rules": []})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)

    def test_enabled_rules_sorted_by_priority_then_name(self):
        from chimera.modules.routing_rules import _rr_enabled_rules
        state = {"rules": [
            {"name": "b", "enabled": True, "priority": 10},
            {"name": "a", "enabled": True, "priority": 10},
            {"name": "z", "enabled": True, "priority": 5},
            {"name": "off", "enabled": False, "priority": 1},
        ]}
        result = _rr_enabled_rules(state)
        self.assertEqual([r["name"] for r in result], ["z", "a", "b"])


# ══════════════════════════════════════════════════════════════════════════════
#  Сборка Xray-правил
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildXrayRules(unittest.TestCase):
    """_rr_build_xray_rules — state-правило → Xray rules."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_simple_domain_rule(self):
        from chimera.modules.routing_rules import (
            _rr_build_xray_rules, RR_COMMENT_PREFIX,
        )
        rule = {"name": "ads", "domains": ["geosite:category-ads-all"],
                "ips": [], "ports": [], "outbound": "block", "priority": 5}
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(err, "")
        self.assertEqual(len(xr), 1)
        self.assertEqual(xr[0]["domain"], ["geosite:category-ads-all"])
        self.assertEqual(xr[0]["outboundTag"], "block")
        self.assertEqual(xr[0]["comment"], f"{RR_COMMENT_PREFIX}ads")
        self.assertEqual(xr[0]["type"], "field")

    def test_and_semantics_multiple_fields(self):
        """domain+ip+port в одном правиле = все поля в одном Xray rule (AND)."""
        from chimera.modules.routing_rules import _rr_build_xray_rules
        rule = {"name": "combo", "domains": ["example.com"],
                "ips": ["1.2.3.0/24"], "ports": ["443"],
                "outbound": "direct", "priority": 10}
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(err, "")
        self.assertEqual(len(xr), 1)
        self.assertEqual(xr[0]["domain"], ["example.com"])
        self.assertEqual(xr[0]["ip"], ["1.2.3.0/24"])
        self.assertEqual(xr[0]["port"], ["443"])

    def test_no_match_returns_error(self):
        from chimera.modules.routing_rules import _rr_build_xray_rules
        rule = {"name": "empty", "domains": [], "ips": [], "ports": [],
                "outbound": "direct", "priority": 10}
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(xr, [])
        self.assertIn("нет ни одного матча", err)

    def test_ip_split_over_500(self):
        """1200 IP → 3 правила по 500, без доменов/портов."""
        from chimera.modules.routing_rules import _rr_build_xray_rules
        ips = [f"10.{i // 256}.{i % 256}.0/24" for i in range(1200)]
        rule = {"name": "big", "domains": [], "ips": ips, "ports": [],
                "outbound": "chain-exit-2", "priority": 10, "chunk": 500}
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(err, "")
        self.assertEqual(len(xr), 3)
        self.assertEqual(len(xr[0]["ip"]), 500)
        self.assertEqual(len(xr[2]["ip"]), 200)
        for r in xr:
            self.assertEqual(r["comment"], "custom:big")

    def test_ip_split_with_domains_rejected(self):
        """Разбивка + домены = отказ (AND нельзя размножить на чанки)."""
        from chimera.modules.routing_rules import _rr_build_xray_rules
        ips = [f"10.{i}.0.0/24" for i in range(600)]
        rule = {"name": "bad", "domains": ["example.com"], "ips": ips,
                "ports": [], "outbound": "direct", "priority": 10}
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(xr, [])
        self.assertIn("не поддерживаются", err)

    def test_custom_chunk(self):
        """chunk=3: 7 IP → 3 правила (3+3+1)."""
        from chimera.modules.routing_rules import _rr_build_xray_rules
        ips = [f"10.0.{i}.0/24" for i in range(7)]
        rule = {"name": "c", "domains": [], "ips": ips, "ports": [],
                "outbound": "direct", "priority": 10, "chunk": 3}
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(err, "")
        self.assertEqual([len(r["ip"]) for r in xr], [3, 3, 1])


# ══════════════════════════════════════════════════════════════════════════════
#  Применение к конфигу
# ══════════════════════════════════════════════════════════════════════════════

class _ConfigFixture(unittest.TestCase):
    """Общий фикс: tmp-каталог с config.json + патчи модуля."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_dir = self._tmpdir / "etc-xray"
        self._cfg_dir.mkdir()
        self._cfg = self._cfg_dir / "config.json"
        self._state = self._tmpdir / "routing_rules.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        from chimera.modules import routing_rules as rr
        return [
            patch.object(rr, "_CONFIG_DIR", self._cfg_dir),
            patch.object(rr, "_ALT_CONFIG", self._tmpdir / "nonexistent.json"),
            patch.object(rr, "RR_STATE_FILE", self._state),
        ]

    def _write_cfg(self, cfg_dict):
        self._cfg.write_text(json.dumps(cfg_dict))

    def _read_cfg(self):
        return json.loads(self._cfg.read_text())


class TestApplyToXray(_ConfigFixture):
    """_rr_apply_to_xray — патч routing.rules."""

    def _base_state(self, rules):
        return {"version": 1, "rules": rules}

    def test_inserts_top_before_builtin_rules(self):
        """top: custom:* вставляются ВЫШЕ dns_custom и ru_subnets_ripe."""
        from chimera.modules import routing_rules as rr
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct",
             "comment": "ru_subnets_ripe"},
            {"type": "field", "domain": ["x.com"], "outboundTag": "direct",
             "comment": "dns_custom:x.com"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._write_cfg(cfg)
        state = self._base_state([
            {"name": "mine", "enabled": True, "domains": ["example.com"],
             "ips": [], "ports": [], "outbound": "chain-exit-2",
             "priority": 10, "placement": "top"},
        ])
        self._state.write_text(json.dumps(state))
        for p in self._patches():
            p.start()
        try:
            with patch.object(rr, "_rr_reload_xray", return_value=True):
                ok = rr._rr_apply_to_xray()
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(ok)
        rules = self._read_cfg()["routing"]["rules"]
        # Порядок: custom:mine → ru_subnets_ripe → dns_custom → catch-all
        self.assertEqual(rules[0]["comment"], "custom:mine")
        self.assertEqual(rules[1]["comment"], "ru_subnets_ripe")
        self.assertEqual(rules[2]["comment"], "dns_custom:x.com")
        self.assertEqual(len(rules), 4)

    def test_before_catchall_placement(self):
        """before_catchall: вставка ПЕРЕД catch-all, ПОСЛЕ встроенных."""
        from chimera.modules import routing_rules as rr
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct",
             "comment": "ru_subnets_ripe"},
            {"type": "field", "domain": ["x.com"], "outboundTag": "direct",
             "comment": "dns_custom:x.com"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._write_cfg(cfg)
        state = self._base_state([
            {"name": "low", "enabled": True, "domains": ["late.com"],
             "ips": [], "ports": [], "outbound": "block",
             "priority": 10, "placement": "before_catchall"},
        ])
        self._state.write_text(json.dumps(state))
        for p in self._patches():
            p.start()
        try:
            with patch.object(rr, "_rr_reload_xray", return_value=True):
                ok = rr._rr_apply_to_xray()
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(ok)
        rules = self._read_cfg()["routing"]["rules"]
        # Порядок: ru_subnets → dns_custom → custom:low → catch-all
        self.assertEqual([r.get("comment") for r in rules],
                         ["ru_subnets_ripe", "dns_custom:x.com",
                          "custom:low", None])

    def test_priority_ordering_within_top(self):
        """Меньше priority = выше; tie-break по имени."""
        from chimera.modules import routing_rules as rr
        self._write_cfg(_make_xray_config())
        state = self._base_state([
            {"name": "b-second", "enabled": True, "domains": ["b.com"],
             "ips": [], "ports": [], "outbound": "direct",
             "priority": 20, "placement": "top"},
            {"name": "a-first", "enabled": True, "domains": ["a.com"],
             "ips": [], "ports": [], "outbound": "direct",
             "priority": 5, "placement": "top"},
            {"name": "c-tie", "enabled": True, "domains": ["c.com"],
             "ips": [], "ports": [], "outbound": "direct",
             "priority": 20, "placement": "top"},
        ])
        self._state.write_text(json.dumps(state))
        for p in self._patches():
            p.start()
        try:
            with patch.object(rr, "_rr_reload_xray", return_value=True):
                rr._rr_apply_to_xray()
        finally:
            for p in self._patches():
                p.stop()
        rules = self._read_cfg()["routing"]["rules"]
        self.assertEqual([r["comment"] for r in rules[:3]],
                         ["custom:a-first", "custom:b-second", "custom:c-tie"])

    def test_removes_stale_custom_rules(self):
        """Старые custom:* (устаревшие имена) удаляются при re-apply."""
        from chimera.modules import routing_rules as rr
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["stale.com"], "outboundTag": "direct",
             "comment": "custom:stale-rule"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._write_cfg(cfg)
        state = self._base_state([
            {"name": "fresh", "enabled": True, "domains": ["fresh.com"],
             "ips": [], "ports": [], "outbound": "direct",
             "priority": 10, "placement": "top"},
        ])
        self._state.write_text(json.dumps(state))
        for p in self._patches():
            p.start()
        try:
            with patch.object(rr, "_rr_reload_xray", return_value=True):
                rr._rr_apply_to_xray()
        finally:
            for p in self._patches():
                p.stop()
        rules = self._read_cfg()["routing"]["rules"]
        comments = [r.get("comment") for r in rules]
        self.assertNotIn("custom:stale-rule", comments)
        self.assertIn("custom:fresh", comments)

    def test_disabled_rules_not_applied_and_removed(self):
        """enabled=false: правило не вставляется, из конфига удаляется."""
        from chimera.modules import routing_rules as rr
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["d.com"], "outboundTag": "direct",
             "comment": "custom:disabled-one"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._write_cfg(cfg)
        state = self._base_state([
            {"name": "disabled-one", "enabled": False, "domains": ["d.com"],
             "ips": [], "ports": [], "outbound": "direct",
             "priority": 10, "placement": "top"},
        ])
        self._state.write_text(json.dumps(state))
        for p in self._patches():
            p.start()
        try:
            with patch.object(rr, "_rr_reload_xray", return_value=True):
                rr._rr_apply_to_xray()
        finally:
            for p in self._patches():
                p.stop()
        rules = self._read_cfg()["routing"]["rules"]
        comments = [r.get("comment") for r in rules]
        self.assertNotIn("custom:disabled-one", comments)

    def test_no_config_returns_false(self):
        """Нет живого конфига → False (не падает)."""
        from chimera.modules import routing_rules as rr
        # config.json не создаём
        for p in self._patches():
            p.start()
        try:
            ok = rr._rr_apply_to_xray()
        finally:
            for p in self._patches():
                p.stop()
        self.assertFalse(ok)

    def test_validate_failure_rolls_back(self):
        """xray run -test fail → конфиг откатывается к исходному."""
        from chimera.modules import routing_rules as rr
        original = _make_xray_config(routing_rules=[
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._write_cfg(original)
        state = self._base_state([
            {"name": "x", "enabled": True, "domains": ["x.com"],
             "ips": [], "ports": [], "outbound": "direct",
             "priority": 10, "placement": "top"},
        ])
        self._state.write_text(json.dumps(state))
        for p in self._patches():
            p.start()
        try:
            bad = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="Failed to start")
            with patch.object(rr, "_rr_reload_xray", return_value=True), \
                 patch.object(rr, "_run", return_value=bad) as m_run:
                ok = rr._rr_apply_to_xray(validate=True)
            # _run мокнут целиком: системные команды не выполняются
            self.assertFalse(ok)
            # Конфиг откачен к исходному: custom:* нет
            rules = self._read_cfg()["routing"]["rules"]
            self.assertEqual([r.get("comment") for r in rules], [None])
        finally:
            for p in self._patches():
                p.stop()

    def test_both_config_paths_patched(self):
        """Альтернативный /usr/local/etc/xray/config.json тоже патчится."""
        from chimera.modules import routing_rules as rr
        alt_dir = self._tmpdir / "usr-local"
        (alt_dir).mkdir()
        alt_cfg = alt_dir / "config.json"
        alt_cfg.write_text(json.dumps(_make_xray_config()))
        for p in self._patches():
            p.start()
        try:
            # Подменяем _ALT_CONFIG на реальный второй конфиг
            with patch.object(rr, "_ALT_CONFIG", alt_cfg):
                self._write_cfg(_make_xray_config())
                state = self._base_state([
                    {"name": "dual", "enabled": True, "domains": ["d.com"],
                     "ips": [], "ports": [], "outbound": "direct",
                     "priority": 10, "placement": "top"},
                ])
                self._state.write_text(json.dumps(state))
                with patch.object(rr, "_rr_reload_xray", return_value=True):
                    ok = rr._rr_apply_to_xray()
                self.assertTrue(ok)
                alt_rules = json.loads(alt_cfg.read_text())["routing"]["rules"]
                self.assertEqual(alt_rules[0]["comment"], "custom:dual")
        finally:
            for p in self._patches():
                p.stop()


class TestCatchall(unittest.TestCase):
    """_rr_is_catchall — по канону ru_subnets."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_network_only_is_catchall(self):
        from chimera.modules.routing_rules import _rr_is_catchall
        self.assertTrue(_rr_is_catchall(
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}))
        self.assertTrue(_rr_is_catchall(
            {"type": "field", "network": "tcp", "outboundTag": "direct"}))

    def test_with_match_not_catchall(self):
        from chimera.modules.routing_rules import _rr_is_catchall
        self.assertFalse(_rr_is_catchall(
            {"type": "field", "network": "tcp,udp", "domain": ["x.com"],
             "outboundTag": "direct"}))
        self.assertFalse(_rr_is_catchall(
            {"type": "field", "network": "tcp,udp", "ip": ["1.2.3.0/24"],
             "outboundTag": "direct"}))
        self.assertFalse(_rr_is_catchall(
            {"type": "field", "network": "tcp,udp", "port": ["443"],
             "outboundTag": "direct"}))
        self.assertFalse(_rr_is_catchall(
            {"type": "field", "domain": ["x.com"], "outboundTag": "direct"}))


# ══════════════════════════════════════════════════════════════════════════════
#  Restore (после regenerate)
# ══════════════════════════════════════════════════════════════════════════════

class TestRestoreRoutingRules(_ConfigFixture):
    """restore_routing_rules_if_needed — re-apply после regenerate."""

    def _state_write(self, rules):
        self._state.write_text(json.dumps({"version": 1, "rules": rules}))

    def test_returns_false_when_state_empty(self):
        """State пуст/нет — ничего не делаем."""
        from chimera.modules import routing_rules as rr
        self._write_cfg(_make_xray_config())
        for p in self._patches():
            p.start()
        try:
            self.assertFalse(rr.restore_routing_rules_if_needed())
        finally:
            for p in self._patches():
                p.stop()

    def test_returns_false_when_all_present(self):
        """Все включённые имена в конфиге → False (уже применено)."""
        from chimera.modules import routing_rules as rr
        self._write_cfg(_make_xray_config(routing_rules=[
            {"type": "field", "domain": ["x.com"], "outboundTag": "direct",
             "comment": "custom:x"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]))
        self._state_write([
            {"name": "x", "enabled": True, "domains": ["x.com"],
             "ips": [], "ports": [], "outbound": "direct", "priority": 10},
        ])
        for p in self._patches():
            p.start()
        try:
            self.assertFalse(rr.restore_routing_rules_if_needed(silent=True))
        finally:
            for p in self._patches():
                p.stop()

    def test_reapplies_after_regenerate(self):
        """Regenerate стёр custom:* → restore пере-применяет."""
        from chimera.modules import routing_rules as rr
        # Конфиг после generate_*: только встроенные правила
        self._write_cfg(_make_xray_config(routing_rules=[
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct",
             "comment": "ru_subnets_ripe"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]))
        self._state_write([
            {"name": "viasily-ru-exit2", "enabled": True, "domains": [],
             "ips": [f"10.{i}.0.0/24" for i in range(600)], "ports": [],
             "outbound": "chain-exit-2", "priority": 10, "chunk": 500},
        ])
        for p in self._patches():
            p.start()
        try:
            with patch.object(rr, "_rr_reload_xray", return_value=True) as m_rl:
                result = rr.restore_routing_rules_if_needed(silent=True)
            self.assertTrue(result, "Должен вернуть True — правила пере-применены")
            # reload НЕ вызывается restore'ом (рестарт делает вызывающий)
            m_rl.assert_not_called()
            rules = self._read_cfg()["routing"]["rules"]
            custom = [r for r in rules
                      if str(r.get("comment", "")).startswith("custom:")]
            self.assertEqual(len(custom), 2)  # 600 IP / 500 = 2 правила
            self.assertEqual(custom[0]["outboundTag"], "chain-exit-2")
            # custom выше ru_subnets_ripe
            self.assertEqual(rules[0].get("comment"), "custom:viasily-ru-exit2")
        finally:
            for p in self._patches():
                p.stop()

    def test_partial_loss_full_reapply(self):
        """Частичная потеря (1 из 2) → полный re-apply (идемпотентно)."""
        from chimera.modules import routing_rules as rr
        self._write_cfg(_make_xray_config(routing_rules=[
            {"type": "field", "domain": ["a.com"], "outboundTag": "direct",
             "comment": "custom:aaa"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]))
        self._state_write([
            {"name": "aaa", "enabled": True, "domains": ["a.com"],
             "ips": [], "ports": [], "outbound": "direct", "priority": 10},
            {"name": "bbb", "enabled": True, "domains": ["b.com"],
             "ips": [], "ports": [], "outbound": "block", "priority": 20},
        ])
        for p in self._patches():
            p.start()
        try:
            result = rr.restore_routing_rules_if_needed(silent=True)
            self.assertTrue(result)
            rules = self._read_cfg()["routing"]["rules"]
            names = [r.get("comment") for r in rules]
            self.assertEqual(names.count("custom:aaa"), 1)
            self.assertEqual(names.count("custom:bbb"), 1)
        finally:
            for p in self._patches():
                p.stop()

    def test_disabled_not_restored(self):
        """Все правила выключены → False, конфиг не трогаем."""
        from chimera.modules import routing_rules as rr
        before = _make_xray_config()
        self._write_cfg(before)
        self._state_write([
            {"name": "off", "enabled": False, "domains": ["off.com"],
             "ips": [], "ports": [], "outbound": "direct", "priority": 10},
        ])
        for p in self._patches():
            p.start()
        try:
            self.assertFalse(rr.restore_routing_rules_if_needed(silent=True))
            self.assertEqual(self._read_cfg()["routing"]["rules"],
                             before["routing"]["rules"])
        finally:
            for p in self._patches():
                p.stop()


class TestRrCustomNames(_ConfigFixture):
    """_rr_custom_names_in_config — сбор имён из comment."""

    def test_collects_names(self):
        from chimera.modules import routing_rules as rr
        self._write_cfg(_make_xray_config(routing_rules=[
            {"type": "field", "domain": ["a.com"], "outboundTag": "direct",
             "comment": "custom:alpha"},
            {"type": "field", "domain": ["b.com"], "outboundTag": "direct",
             "comment": "custom:beta"},
            {"type": "field", "domain": ["c.com"], "outboundTag": "direct",
             "comment": "dns_custom:gamma"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]))
        for p in self._patches():
            p.start()
        try:
            names = rr._rr_custom_names_in_config()
        finally:
            for p in self._patches():
                p.stop()
        self.assertEqual(names, {"alpha", "beta"})


class TestRuSubnetsImportBuild(unittest.TestCase):
    """Сборка правила-импорта РФ-подсетей (без TUI — только build)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ru_import_rule_splits(self):
        """source=ru_subnets_import с 1200 CIDR → 3 правила по 500."""
        from chimera.modules.routing_rules import (
            _rr_build_xray_rules, RR_DEFAULT_CHUNK,
        )
        cidrs = [f"5.{i // 256}.{i % 256}.0/24" for i in range(1200)]
        rule = {
            "name": "ru-subnets-via-chain-exit-2",
            "enabled": True, "domains": [], "ips": sorted(cidrs), "ports": [],
            "outbound": "chain-exit-2", "priority": 10,
            "placement": "top", "chunk": RR_DEFAULT_CHUNK,
            "source": "ru_subnets_import",
        }
        xr, err = _rr_build_xray_rules(rule)
        self.assertEqual(err, "")
        self.assertEqual(len(xr), 3)
        self.assertEqual(xr[0]["comment"], "custom:ru-subnets-via-chain-exit-2")
        # Ни в одном правиле нет domain/port — только ip
        for r in xr:
            self.assertNotIn("domain", r)
            self.assertNotIn("port", r)
            self.assertEqual(r["outboundTag"], "chain-exit-2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
