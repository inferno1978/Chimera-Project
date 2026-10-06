#!/usr/bin/env python3
"""
tests/test_chain_relay.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/chain_relay.py — релейные хопы (многохоповый
каскад, Xray sockopt.dialerProxy).

Покрывает:
  1. validate_hops — дубли тегов, reserved-теги, битые UUID, self-via,
     циклы длины >1, битые ссылки via, обязательные REALITY-поля.
  2. hop_via_tag_for / hop_chain — разрешение via (нет/выключен/цикл).
  3. build_hop_outbound — три формы протокола (reality/xhttp/xhttp_reality),
     dialerProxy у хопа с via, flow-default для reality.
  4. collect_hop_outbounds — только используемые хопи, рекурсия via,
     дедупликация, пустой результат без via (байт-в-байт совместимость).
  5. build_check_client_config — форма конфига full-path чекера.
  6. Интеграция генерации: generate_xray_config_chain_entry_multi с via
     (dialerProxy на exit-outbound + hop-outbound в конфиге) и БЕЗ хопов
     (outbounds не меняются).
  7. node_health_monitor: via-нода → full-path чек вместо TCP.

Реального subprocess/systemctl/curl — нет, всё через mock.
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
    """Фейк chimera._core в sys.modules (эталонный паттерн test_chain_nodes)."""
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


_UUID = "d34df00d-1111-2222-3333-444455556666"


def _mk_hop(tag="hop-a", host="fi.example.com", via="", enabled=True,
            proto="reality"):
    return {
        "tag": tag, "host": host, "port": 443, "uuid": _UUID,
        "pubkey": "RkFLRS1yZWFsaXR5LXB1YmxpYy1rZXktMTIzNDU2Nzg",
        "shortid": "0f1e2d3c4b5a6978", "sni": host,
        "fp": "firefox", "flow": "xtls-rprx-vision", "proto": proto,
        "path": "/", "xhttp_mode": "stream-up", "via": via,
        "comment": "", "enabled": enabled,
    }


def _mk_node(host="ee.example.com", via=""):
    return {
        "host": host, "port": 443, "uuid": _UUID,
        "pubkey": "Q0hBSU1FUkEtZmFrZS1wYi1rZXktMDAwMDAwMDAwMDA",
        "shortid": "a1b2c3d4e5f60718", "sni": host,
        "fp": "firefox", "flow": "xtls-rprx-vision", "proto": "reality",
        "path": "/", "xhttp_mode": "stream-up", "via": via,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  validate_hops
# ══════════════════════════════════════════════════════════════════════════════
class TestValidateHops(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_hops_no_errors(self):
        from chimera.modules.chain_relay import validate_hops
        self.assertEqual(validate_hops([_mk_hop()]), [])

    def test_duplicate_tag(self):
        from chimera.modules.chain_relay import validate_hops
        errs = validate_hops([_mk_hop("hop-a"), _mk_hop("hop-a", host="b.com")])
        self.assertTrue(any("дублир" in e for e in errs))

    def test_reserved_tag(self):
        from chimera.modules.chain_relay import validate_hops
        errs = validate_hops([_mk_hop("direct")])
        self.assertTrue(any("зарезервирован" in e for e in errs))

    def test_bad_uuid(self):
        from chimera.modules.chain_relay import validate_hops
        h = _mk_hop()
        h["uuid"] = "not-a-uuid"
        errs = validate_hops([h])
        self.assertTrue(any("UUID" in e for e in errs))

    def test_self_via_cycle(self):
        from chimera.modules.chain_relay import validate_hops
        h = _mk_hop("hop-a", via="hop-a")
        errs = validate_hops([h])
        self.assertTrue(any("цикл" in e or "себя" in e for e in errs))

    def test_long_cycle(self):
        from chimera.modules.chain_relay import validate_hops
        a = _mk_hop("hop-a", via="hop-b")
        b = _mk_hop("hop-b", host="b.com", via="hop-a")
        errs = validate_hops([a, b])
        self.assertTrue(any("цикл" in e for e in errs))

    def test_broken_via_reference(self):
        from chimera.modules.chain_relay import validate_hops
        h = _mk_hop("hop-a", via="hop-ghost")
        errs = validate_hops([h])
        self.assertTrue(any("не существует" in e for e in errs))

    def test_reality_requires_pbk(self):
        from chimera.modules.chain_relay import validate_hops
        h = _mk_hop()
        h["pubkey"] = ""
        errs = validate_hops([h])
        self.assertTrue(any("pbk" in e for e in errs))

    def test_via_for_nodes_unknown_tag(self):
        from chimera.modules.chain_relay import validate_via_for_nodes
        errs = validate_via_for_nodes([_mk_node(via="hop-ghost")], [_mk_hop()])
        self.assertEqual(len(errs), 1)


# ══════════════════════════════════════════════════════════════════════════════
#  hop_via_tag_for / hop_chain
# ══════════════════════════════════════════════════════════════════════════════
class TestHopResolution(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_no_via_returns_none(self):
        from chimera.modules.chain_relay import hop_via_tag_for
        self.assertIsNone(hop_via_tag_for(_mk_node(), [_mk_hop()]))

    def test_via_resolves(self):
        from chimera.modules.chain_relay import hop_via_tag_for
        self.assertEqual(
            hop_via_tag_for(_mk_node(via="hop-a"), [_mk_hop()]), "hop-a")

    def test_disabled_hop_returns_none(self):
        from chimera.modules.chain_relay import hop_via_tag_for
        hops = [_mk_hop(enabled=False)]
        self.assertIsNone(hop_via_tag_for(_mk_node(via="hop-a"), hops))

    def test_missing_hop_returns_none(self):
        from chimera.modules.chain_relay import hop_via_tag_for
        self.assertIsNone(hop_via_tag_for(_mk_node(via="hop-x"), [_mk_hop()]))

    def test_chain_recursive(self):
        from chimera.modules.chain_relay import hop_chain
        a = _mk_hop("hop-a", via="hop-b")
        b = _mk_hop("hop-b", host="b.com")
        self.assertEqual([h["tag"] for h in hop_chain("hop-a", [a, b])],
                         ["hop-a", "hop-b"])

    def test_chain_cycle_returns_empty(self):
        from chimera.modules.chain_relay import hop_chain
        a = _mk_hop("hop-a", via="hop-b")
        b = _mk_hop("hop-b", host="b.com", via="hop-a")
        self.assertEqual(hop_chain("hop-a", [a, b]), [])

    def test_chain_broken_link_returns_empty(self):
        from chimera.modules.chain_relay import hop_chain
        a = _mk_hop("hop-a", via="hop-ghost")
        self.assertEqual(hop_chain("hop-a", [a]), [])


# ══════════════════════════════════════════════════════════════════════════════
#  build_hop_outbound
# ══════════════════════════════════════════════════════════════════════════════
class TestBuildHopOutbound(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_reality_shape(self):
        from chimera.modules.chain_relay import build_hop_outbound
        out = build_hop_outbound(_mk_hop())
        self.assertEqual(out["tag"], "hop-a")
        self.assertEqual(out["protocol"], "vless")
        ss = out["streamSettings"]
        self.assertEqual(ss["network"], "tcp")
        self.assertEqual(ss["security"], "reality")
        rs = ss["realitySettings"]
        self.assertEqual(rs["publicKey"], "RkFLRS1yZWFsaXR5LXB1YmxpYy1rZXktMTIzNDU2Nzg")
        self.assertEqual(rs["shortId"], "0f1e2d3c4b5a6978")
        user = out["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["id"], _UUID)
        self.assertEqual(user["flow"], "xtls-rprx-vision")
        self.assertNotIn("dialerProxy", ss.get("sockopt", {}))

    def test_reality_flow_default_filled(self):
        from chimera.modules.chain_relay import build_hop_outbound
        h = _mk_hop()
        h["flow"] = ""
        out = build_hop_outbound(h)
        self.assertEqual(
            out["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision")

    def test_via_sets_dialer_proxy(self):
        from chimera.modules.chain_relay import build_hop_outbound
        out = build_hop_outbound(_mk_hop(via="hop-b"))
        self.assertEqual(
            out["streamSettings"]["sockopt"]["dialerProxy"], "hop-b")

    def test_xhttp_shape_no_flow(self):
        from chimera.modules.chain_relay import build_hop_outbound
        out = build_hop_outbound(_mk_hop(proto="xhttp"))
        ss = out["streamSettings"]
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "tls")
        self.assertIn("tlsSettings", ss)
        self.assertNotIn("flow", out["settings"]["vnext"][0]["users"][0])

    def test_xhttp_reality_shape(self):
        from chimera.modules.chain_relay import build_hop_outbound
        out = build_hop_outbound(_mk_hop(proto="xhttp_reality"))
        ss = out["streamSettings"]
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "reality")
        self.assertIn("realitySettings", ss)
        self.assertIn("xhttpSettings", ss)


# ══════════════════════════════════════════════════════════════════════════════
#  collect_hop_outbounds
# ══════════════════════════════════════════════════════════════════════════════
class TestCollectHopOutbounds(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_without_via(self):
        """РЕГРЕССИЯ: без via → hop-outbound-ов нет (конфиг не меняется)."""
        from chimera.modules.chain_relay import collect_hop_outbounds
        hops = [_mk_hop()]
        self.assertEqual(collect_hop_outbounds([_mk_node()], hops), [])

    def test_collects_referenced_only(self):
        from chimera.modules.chain_relay import collect_hop_outbounds
        used = _mk_hop("hop-used")
        unused = _mk_hop("hop-unused", host="x.com")
        out = collect_hop_outbounds([_mk_node(via="hop-used")], [used, unused])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["tag"], "hop-used")

    def test_recursive_via_and_dedup(self):
        from chimera.modules.chain_relay import collect_hop_outbounds
        a = _mk_hop("hop-a", via="hop-b")
        b = _mk_hop("hop-b", host="b.com")
        # две ноды через hop-a → hop-b один раз
        nodes = [_mk_node(via="hop-a"), _mk_node(host="ee2.com", via="hop-b")]
        out = collect_hop_outbounds(nodes, [a, b])
        tags = [o["tag"] for o in out]
        self.assertEqual(tags, ["hop-a", "hop-b"])

    def test_disabled_hop_excluded(self):
        from chimera.modules.chain_relay import collect_hop_outbounds
        hops = [_mk_hop(enabled=False)]
        self.assertEqual(collect_hop_outbounds([_mk_node(via="hop-a")], hops), [])


# ══════════════════════════════════════════════════════════════════════════════
#  build_check_client_config (full-path чекер)
# ══════════════════════════════════════════════════════════════════════════════
class TestCheckClientConfig(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_shape(self):
        from chimera.modules.chain_relay import build_check_client_config
        cfg = build_check_client_config(
            _mk_node(via="hop-a"), [_mk_hop()], 19099)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg["inbounds"][0]["port"], 19099)
        self.assertEqual(cfg["inbounds"][0]["listen"], "127.0.0.1")
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertEqual(tags, ["hop-a", "exit-check"])
        exit_ob = cfg["outbounds"][-1]
        self.assertEqual(
            exit_ob["streamSettings"]["sockopt"]["dialerProxy"], "hop-a")
        rule = cfg["routing"]["rules"][0]
        self.assertEqual(rule["outboundTag"], "exit-check")

    def test_none_without_via(self):
        from chimera.modules.chain_relay import build_check_client_config
        self.assertIsNone(
            build_check_client_config(_mk_node(), [_mk_hop()], 19099))

    def test_none_with_broken_chain(self):
        from chimera.modules.chain_relay import build_check_client_config
        a = _mk_hop("hop-a", via="hop-b")
        b = _mk_hop("hop-b", host="b.com", via="hop-a")
        self.assertIsNone(
            build_check_client_config(_mk_node(via="hop-a"), [a, b], 19099))


# ══════════════════════════════════════════════════════════════════════════════
#  Интеграция: генерация конфига каскада с via
# ══════════════════════════════════════════════════════════════════════════════
class TestGenerationIntegration(unittest.TestCase):
    """generate_xray_config_chain_entry_multi: dialerProxy + hop-outbound-ы.

    _rebuild_and_restart_xray мокается — реального xray/systemctl нет.
    """

    def setUp(self):
        core = _setup_core_in_sysmodules()
        self.core = core
        self._tmp = tempfile.TemporaryDirectory()
        core.STATE_FILE = Path(self._tmp.name) / "state.json"
        core.CONFIG_DIR = Path(self._tmp.name) / "etc_xray"
        core.XRAY_BIN = "xray-bin-stub"
        # state: Mode B + 2 ноды, вторая через хоп
        self.hops = [_mk_hop("hop-a", host="fi.example.com")]
        nodes = [_mk_node("ee.example.com", via="hop-a"),
                 _mk_node("de.example.com", via="")]
        core.STATE_FILE.write_text(json.dumps({
            "install_mode": "B",
            "protocol_mode": "reality",
            "server_port": 443,
            "domain": "entry.example.com",
            "uuid": _UUID,
            "public_key": "PK", "private_key": "SK", "short_id": "SID",
            "socket": "/dev/shm/x.socket", "spiderx": "/",
            "chain_nodes": nodes,
            "relay_hops": self.hops,
            "chain_balancer_strategy": "roundRobin",
            "chain_pinned_node_index": -1,
        }))
        # генератор читает core-глобали (getattr(core, ...)) — выставляем
        core.CHAIN_NODES = nodes
        core.PROTOCOL_MODE = "reality"
        core.INSTALL_MODE = "B"
        core.SERVER_PORT = 443
        core.PARAM_DOMAIN = "entry.example.com"
        core.PARAM_UUID = _UUID
        core.PARAM_PUBLIC_KEY = "PK"
        core.PARAM_PRIVATE_KEY = "SK"
        core.PARAM_SHORTID = "SID"
        core.PARAM_SOCKET_PATH = str(Path(self._tmp.name) / "x.socket")
        core.PARAM_SPIDERX = "/"
        core.PARAM_REALITY_DEST = ""
        core.AWG_EXIT_ENABLED = False
        core.H2_EXIT_ENABLED = False
        core.SPLIT_TUNNEL_ENABLED = False
        core.CHAIN_BALANCER_STRATEGY = "roundRobin"
        core.CHAIN_PINNED_NODE_INDEX = -1
        # _run мокаем: xray -test возвращает 0
        core._run = lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr="")
        core._rebuild_and_restart_xray = MagicMock()
        core._identity_params_recover = lambda: None
        core._assert_reality_dest_sane = lambda: None

    def tearDown(self):
        self._tmp.cleanup()

    def _generate(self):
        from chimera.modules.chain_nodes import (
            generate_xray_config_chain_entry_multi)
        # цепочка читает core.CHAIN_NODES заново — синхронизируем с state
        st = json.loads(self.core.STATE_FILE.read_text())
        self.core.CHAIN_NODES = st.get("chain_nodes", [])
        generate_xray_config_chain_entry_multi()
        cfg_file = self.core.CONFIG_DIR / "config.json"
        return json.loads(cfg_file.read_text())

    def test_via_node_gets_dialer_proxy_and_hop_outbound(self):
        cfg = self._generate()
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertIn("hop-a", tags)
        ee_ob = next(o for o in cfg["outbounds"] if o["tag"] == "chain-exit-1")
        self.assertEqual(
            ee_ob["streamSettings"]["sockopt"]["dialerProxy"], "hop-a")
        # прямая нода — БЕЗ dialerProxy
        de_ob = next(o for o in cfg["outbounds"] if o["tag"] == "chain-exit-2")
        self.assertNotIn(
            "dialerProxy", de_ob["streamSettings"].get("sockopt", {}))

    def test_no_hops_config_unchanged_shape(self):
        """Без relay_hips в state — hop-outbound-ов нет и dialerProxy нет."""
        st = json.loads(self.core.STATE_FILE.read_text())
        st["relay_hops"] = []
        st["chain_nodes"] = [_mk_node("ee.example.com")]   # без via
        self.core.STATE_FILE.write_text(json.dumps(st))
        cfg = self._generate()
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertNotIn("hop-a", tags)
        for o in cfg["outbounds"]:
            if o.get("tag", "").startswith("chain-exit"):
                self.assertNotIn(
                    "dialerProxy", o.get("streamSettings", {}).get("sockopt", {}))

    def test_disabled_hop_falls_back_direct(self):
        """Выключенный хоп → dialerProxy НЕ ставится (прямой путь)."""
        st = json.loads(self.core.STATE_FILE.read_text())
        st["relay_hops"] = [_mk_hop("hop-a", enabled=False)]
        self.core.STATE_FILE.write_text(json.dumps(st))
        cfg = self._generate()
        ee_ob = next(o for o in cfg["outbounds"] if o["tag"] == "chain-exit-1")
        self.assertNotIn(
            "dialerProxy", ee_ob["streamSettings"].get("sockopt", {}))
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertNotIn("hop-a", tags)


# ══════════════════════════════════════════════════════════════════════════════
#  node_health_monitor: via → full-path
# ══════════════════════════════════════════════════════════════════════════════
class TestHealthMonitorVia(unittest.TestCase):

    def setUp(self):
        core = _setup_core_in_sysmodules()
        self.core = core
        self._tmp = tempfile.TemporaryDirectory()
        core.STATE_FILE = Path(self._tmp.name) / "state.json"
        self.hops = [_mk_hop("hop-a")]
        core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [_mk_node(via="hop-a"), _mk_node("de.example.com")],
            "relay_hops": self.hops,
        }))
        # nhm имеет СОБСТВЕННЫЕ константы путей — патчим их в tmp
        from chimera.modules import node_health_monitor as _nhm
        self._nhm = _nhm
        self._orig_paths = (_nhm.STATE_FILE, _nhm.HEALTH_STATE, _nhm.HEALTH_LOG)
        _nhm.STATE_FILE = core.STATE_FILE
        _nhm.HEALTH_STATE = Path(self._tmp.name) / "node-health-state.json"
        _nhm.HEALTH_LOG = Path(self._tmp.name) / "xray-node-health.log"

    def tearDown(self):
        (self._nhm.STATE_FILE, self._nhm.HEALTH_STATE, self._nhm.HEALTH_LOG) = \
            self._orig_paths
        self._tmp.cleanup()

    def test_via_node_uses_full_path_check(self):
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        calls = []

        def fake_full_path(nd, hops, **kw):
            calls.append(nd["host"])
            return {"ok": True, "ms": 421.0, "exit_ip": "203.0.113.10",
                    "detail": "цепочка жива"}

        # патчим модуль chain_relay (ленивый import внутри nhm возьмёт патченный атрибут)
        orig = cr.check_via_node_full_path
        cr.check_via_node_full_path = fake_full_path
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 5.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_via_node_full_path = orig
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        self.assertTrue(by_host["ee.example.com"]["up"])
        self.assertEqual(by_host["ee.example.com"]["ms"], 421.0)
        self.assertTrue(by_host["de.example.com"]["up"])
        # full-path вызван только для via-ноды, TCP — только для прямой
        self.assertEqual(calls, ["ee.example.com", "tcp:de.example.com"])


# ══════════════════════════════════════════════════════════════════════════════
#  check_via_node_full_path: want_speed_mb (скорость через цепочку)
# ══════════════════════════════════════════════════════════════════════════════
class TestFullPathSpeed(unittest.TestCase):
    """want_speed_mb>0 → качает файл ЧЕРЕЗ socks-цепочку и возвращает
    speed_mbps; want_speed_mb=0 (дефолт) → скорость не меряется (обратная
    совместимость HM/шага 5)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self.hops = [_mk_hop("hop-a")]
        self.nd = _mk_node(via="hop-a")

    def _run_check(self, calls, **kw):
        """Запуск check_via_node_full_path с полностью замоканным окружением."""
        import chimera.modules.chain_relay as cr

        class _FakeProc:
            def poll(self):
                return None
            def terminate(self):
                pass
            def wait(self, timeout=None):
                pass
            def kill(self):
                pass
            stderr = b""

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if "generate_204" in " ".join(map(str, cmd)):
                # liveness-проба: HTTP 204, 0.25 c
                return types.SimpleNamespace(returncode=0,
                                             stdout="204 0.25",
                                             stderr="")
            if "api.ipify.org" in " ".join(map(str, cmd)):
                return types.SimpleNamespace(returncode=0,
                                             stdout="203.0.113.77\n",
                                             stderr="")
            if "speed.cloudflare.com" in " ".join(map(str, cmd)):
                # download 10 МБ за 2 c = 5242880 Б/с = 41.9 Мбит/с
                return types.SimpleNamespace(
                    returncode=0,
                    stdout="10485760 2.0 5242880.0", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch.object(cr, "_find_xray_bin", return_value="/usr/local/bin/xray"), \
             patch.object(cr.subprocess, "Popen", return_value=_FakeProc()), \
             patch.object(cr.subprocess, "run", side_effect=fake_run), \
             patch.object(cr.tempfile, "mkstemp",
                          return_value=(99, "/tmp/relaycheck_test.json")), \
             patch("os.write", lambda *a, **kw: None), \
             patch("os.close", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, **kw: None):
            return cr.check_via_node_full_path(self.nd, self.hops, **kw)

    def test_speed_measured_when_requested(self):
        calls = []
        res = self._run_check(calls, want_ip=True, want_speed_mb=10)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["exit_ip"], "203.0.113.77")
        self.assertAlmostEqual(res["speed_mbps"], 41.9, delta=0.2)
        # среди curl-вызовов есть download через socks-цепочку
        self.assertTrue(any("speed.cloudflare.com" in " ".join(map(str, c))
                            for c in calls))

    def test_no_speed_probe_by_default(self):
        calls = []
        res = self._run_check(calls)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["speed_mbps"], 0.0)
        # download-проба не выполнялась
        self.assertFalse(any("speed.cloudflare.com" in " ".join(map(str, c))
                             for c in calls))

    def test_chain_dead_no_speed(self):
        import chimera.modules.chain_relay as cr

        class _FakeProc:
            def poll(self):
                return None
            def terminate(self):
                pass
            def wait(self, timeout=None):
                pass
            def kill(self):
                pass
            stderr = b""

        def fake_run(cmd, **kwargs):
            return types.SimpleNamespace(returncode=0, stdout="000 20.0",
                                         stderr="")

        with patch.object(cr, "_find_xray_bin", return_value="/usr/local/bin/xray"), \
             patch.object(cr.subprocess, "Popen", return_value=_FakeProc()), \
             patch.object(cr.subprocess, "run", side_effect=fake_run), \
             patch.object(cr.tempfile, "mkstemp",
                          return_value=(99, "/tmp/relaycheck_test.json")), \
             patch("os.write", lambda *a, **kw: None), \
             patch("os.close", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, **kw: None):
            res = cr.check_via_node_full_path(self.nd, self.hops,
                                              want_ip=True, want_speed_mb=10)
        self.assertFalse(res["ok"])
        self.assertEqual(res["speed_mbps"], 0.0)
        self.assertEqual(res["exit_ip"], "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
