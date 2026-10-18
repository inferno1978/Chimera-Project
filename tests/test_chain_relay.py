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

    def test_disabled_hop_falls_back_direct_probe(self):
        """via указывает на ВЫКЛЮЧЕННЫЙ хоп: генератор прод-конфига в этом
        случае не ставит dialerProxy (нода ходит напрямую) — HM проверяет
        её КАК ПРЯМУЮ: REALITY-нода с ключами → полный зонд (голый TCP на
        REALITY-порт chimera-ноды — бан-фуд, кейс окт.2026 №3; ранее тут
        был голый TCP — регрессия №4 закрыта), без ключей → TCP. Не врёт
        DOWN «via не найден» (ложный DOWN + TG-тревога при живой ноде)."""
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm

        # Тот же state, но хоп выключен
        self.core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [_mk_node(via="hop-a"), _mk_node("de.example.com")],
            "relay_hops": [_mk_hop("hop-a", enabled=False)],
        }))
        calls = []

        def fake_fp(nd, **kw):
            calls.append("fp:" + nd["host"])
            return {"ok": True, "ms": 33.0, "infra": False}

        orig_fp = cr.check_node_full_path
        cr.check_node_full_path = fake_fp
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 12.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path = orig_fp
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        # via-нода с выключенным хопом ЖИВА — проверена прямым полным
        # зондом (как прямая нода с ключами), НЕ голым TCP
        self.assertTrue(by_host["ee.example.com"]["up"])
        self.assertEqual(by_host["ee.example.com"]["ms"], 33.0)
        # обе ноды (via с выключенным хопом и прямая) — с ключами →
        # обе зондируются прямым полным зондом, TCP не вызывается
        self.assertEqual(calls, ["fp:ee.example.com", "fp:de.example.com"])

    def test_disabled_hop_without_creds_uses_tcp(self):
        """via-нода с выключенным хопом и БЕЗ клиентских ключей — прямой
        полный зонд неприменим: честный TCP-пинг (как раньше)."""
        from chimera.modules import node_health_monitor as nhm

        self.core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [_mk_node(via="hop-a")],
            "relay_hops": [_mk_hop("hop-a", enabled=False)],
        }))
        st = json.loads(self.core.STATE_FILE.read_text())
        st["chain_nodes"] = [{k: v for k, v in st["chain_nodes"][0].items()
                              if k not in ("uuid", "pubkey", "shortid")}]
        self.core.STATE_FILE.write_text(json.dumps(st))
        calls = []
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 44.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        self.assertTrue(by_host["ee.example.com"]["up"])
        self.assertEqual(by_host["ee.example.com"]["ms"], 44.0)
        self.assertEqual(calls, ["tcp:ee.example.com"])

    def test_via_infra_falls_back_tcp(self):
        """Сбой МЕХАНИЗМА via-зонда (нет xray-бинарня и т.п.) — о ноде
        ничего не говорит: честный TCP-fallback, а не ложный DOWN
        (зеркалит infra-флаг check_via_node_full_path, кейс №4)."""
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        # только via-нода (прямая нода с ключами ушла бы в реальный
        # check_node_full_path и зашумляла бы счётчик вызовов)
        self.core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [_mk_node(via="hop-a")],
            "relay_hops": self.hops,
        }))
        calls = []

        def fake_via(nd, hops, **kw):
            calls.append("via:" + nd["host"])
            return {"ok": False, "ms": 0.0, "reason": "нет xray",
                    "infra": True}

        orig = cr.check_via_node_full_path
        cr.check_via_node_full_path = fake_via
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 21.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_via_node_full_path = orig
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        self.assertTrue(by_host["ee.example.com"]["up"])
        self.assertEqual(by_host["ee.example.com"]["ms"], 21.0)
        self.assertEqual(calls, ["via:ee.example.com", "tcp:ee.example.com"])


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
             patch.object(cr, "_resolve_probe_host_ipv4", lambda: None), \
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
             patch.object(cr, "_resolve_probe_host_ipv4", lambda: None), \
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


# ══════════════════════════════════════════════════════════════════════════════
#  check_via_node_full_path v2: probe-ladder + deep-диагностика ног
#  (живой кейс окт. 2026: exit резал порт 80 → вечный ложный «HTTP 000»)
# ══════════════════════════════════════════════════════════════════════════════
class TestProbeLadder(unittest.TestCase):
    """Лестница проб http → https → IP-literal различает отказы."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _ladder(self, responses, probe_ip=None):
        """responses — (rc, code, ms) по порядку вызовов _curl_socks.
        probe_ip — что отвечает _resolve_probe_host_ipv4 (None → P2b
        пропускается: тесты не ходят в реальный DNS)."""
        import chimera.modules.chain_relay as cr
        seq = list(responses)
        self.curl_calls = []

        def fake_curl(port, url, timeout, insecure=False, resolve=None):
            self.curl_calls.append((url, timeout, insecure, resolve))
            return seq.pop(0) if seq else (28, "000", None)

        with patch.object(cr, "_curl_socks", side_effect=fake_curl), \
             patch.object(cr, "_resolve_probe_host_ipv4",
                          return_value=probe_ip):
            return cr._probe_ladder(12345, 20)

    def test_http_204_first(self):
        r = self._ladder([(0, "204", 250.0)])
        self.assertTrue(r["delivered"])
        self.assertTrue(r["domain_ok"])
        self.assertEqual(r["code"], "204")
        self.assertFalse(r["port80_blocked"])
        self.assertFalse(r["ip_only"])

    def test_https_fallback_port80_blocked(self):
        # P1 (http, порт 80) молчит, P2 (https) отвечает → цепь жива,
        # 80-й режется на exit (живой кейс: exit-сеть с ограниченным egress)
        r = self._ladder([(0, "000", 20000.0), (0, "204", 300.0)])
        self.assertTrue(r["delivered"])
        self.assertTrue(r["domain_ok"])
        self.assertTrue(r["port80_blocked"])
        self.assertFalse(r["ip_only"])
        self.assertEqual(r["code"], "204")

    def test_ip_only_dns_broken(self):
        # доменные пробы молчат (P1 + P2 обе попытки), IP-проба отвечает
        # → DNS на exit сломан (P2b пропущен: entry-резолв недоступен)
        r = self._ladder([(0, "000", None), (0, "000", None),
                          (0, "000", None), (0, "301", 400.0)])
        self.assertTrue(r["delivered"])
        self.assertFalse(r["domain_ok"])
        self.assertTrue(r["ip_only"])
        # P3 — четвёртый вызов, без --resolve
        url, timeout, insecure, resolve = self.curl_calls[3]
        self.assertEqual(url, "https://1.1.1.1/")
        self.assertTrue(insecure)
        self.assertIsNone(resolve)

    def test_all_dead(self):
        r = self._ladder([(28, "000", None)] * 5)
        self.assertFalse(r["delivered"])
        self.assertFalse(r["domain_ok"])
        self.assertEqual(r["code"], "")

    def test_non_204_http_code_still_delivered(self):
        # перехват/кэш отдаёт 302 вместо 204 — цепь ДОСТАВЛЯЕТ трафик
        r = self._ladder([(0, "302", 250.0)])
        self.assertTrue(r["delivered"])
        self.assertTrue(r["domain_ok"])
        self.assertEqual(r["code"], "302")

    def test_startup_retry_on_rc7(self):
        # rc=7 (socks ещё не поднялся) → ретраи вместо ложного FAIL
        import chimera.modules.chain_relay as cr
        calls = []

        def fake_curl(port, url, timeout, insecure=False, resolve=None):
            calls.append(url)
            if len(calls) == 1:
                return (7, "000", None)
            return (0, "204", 250.0)

        with patch.object(cr, "_curl_socks", side_effect=fake_curl), \
             patch.object(cr.time, "sleep", lambda s: None):
            r = cr._probe_ladder(12345, 20)
        self.assertTrue(r["domain_ok"])
        self.assertEqual(len(calls), 2)

    def test_https_retry_rescues_slow_chain(self):
        # живой кейс окт. 2026 (вечер): P1 (порт 80) молчит, P2#1 не
        # уложилась в таймаут на медленной цепи (~400 мс RTT), P2#2 —
        # прошла → цепь жива, никакого «нода не отвечает»
        r = self._ladder([(28, "000", None), (28, "000", None),
                          (0, "204", 1500.0)])
        self.assertTrue(r["delivered"])
        self.assertTrue(r["domain_ok"])
        self.assertTrue(r["port80_blocked"])
        self.assertEqual(r["code"], "204")
        # вторая попытка щедрее по таймауту (8 → 10 с)
        self.assertEqual(self.curl_calls[1][1], 8)
        self.assertEqual(self.curl_calls[2][1], 10)

    def test_p2b_resolve_fallback_cf_edge(self):
        # доменные пробы молчат (в т.ч. DNS на exit), P2b с --resolve на
        # entry-резолвленный IP доставляет → ip_only (цепь жива, DNS нет)
        r = self._ladder([(28, "000", None), (28, "000", None),
                          (28, "000", None), (0, "204", 700.0)],
                         probe_ip="104.16.123.96")
        self.assertTrue(r["delivered"])
        self.assertFalse(r["domain_ok"])
        self.assertTrue(r["ip_only"])
        url, timeout, insecure, resolve = self.curl_calls[3]
        self.assertEqual(url, "https://cp.cloudflare.com/generate_204")
        self.assertFalse(insecure)
        self.assertEqual(resolve, "cp.cloudflare.com:443:104.16.123.96")

    def test_p2b_skipped_when_entry_dns_dead(self):
        # entry-резолв не дал IP → P2b пропускается, работают P3/P4
        r = self._ladder([(28, "000", None), (28, "000", None),
                          (28, "000", None), (0, "301", 400.0)],
                         probe_ip=None)
        self.assertTrue(r["delivered"])
        self.assertTrue(r["ip_only"])
        # ни один вызов не ушёл с --resolve
        self.assertTrue(all(c[3] is None for c in self.curl_calls))


class TestDiagnoseDeadChain(unittest.TestCase):
    """Диагностика ног при полном отказе: хоп / нода напрямую / обе."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self.hops = [_mk_hop("hop-a")]
        self.nd = _mk_node(via="hop-a")

    def _diag(self, hop_delivered, direct_delivered):
        import chimera.modules.chain_relay as cr

        def _res(ok):
            return {"delivered": ok, "domain_ok": ok,
                    "code": "204" if ok else "", "ms": 100.0,
                    "port80_blocked": False, "ip_only": False}

        results = iter([_res(hop_delivered), _res(direct_delivered)])

        class _FakeClient:
            start_error = ""

            def __init__(self, cfg, xbin):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def alive(self):
                return True

            def err_tail(self, limit=240):
                return ""

        with patch.object(cr, "_TempXrayClient", _FakeClient), \
             patch.object(cr, "_probe_ladder",
                          lambda *a, **kw: next(results)), \
             patch.object(cr, "_free_local_port", lambda: 4711):
            return cr._diagnose_dead_chain(self.nd, [self.hops[0]],
                                           "/usr/local/bin/xray", 20)

    def test_hop_broken_direct_ok(self):
        d = self._diag(hop_delivered=False, direct_delivered=True)
        self.assertEqual(d["legs"], {"hop": "fail", "direct": "ok"})
        self.assertEqual(d["reason"], "хоп не отвечает")
        self.assertIn("uuid/pbk/sid/sni/flow", d["detail"])

    def test_hop_ok_direct_ok(self):
        # обе ноги по отдельности живы → сломана именно хоп→нода
        d = self._diag(True, True)
        self.assertEqual(d["legs"], {"hop": "ok", "direct": "ok"})
        self.assertEqual(d["reason"], "хоп->нода недостижима")
        self.assertIn("с хопа", d["detail"])

    def test_hop_ok_direct_fail(self):
        # живой кейс окт. 2026 (вечер): «нода не отвечает» противоречил
        # ICMP exit↔хоп и полному тесту (шаг 5/12 ОК); теперь вердикт —
        # про ногу хоп→нода, а не «смерть ноды», с оговоркой про ТСПУ
        # (прямой fail для via-ноды — норма) и подсказкой перепроверки
        d = self._diag(True, False)
        self.assertEqual(d["legs"], {"hop": "ok", "direct": "fail"})
        self.assertEqual(d["reason"], "хоп->нода не доставляет")
        self.assertNotEqual(d["reason"], "нода не отвечает")
        self.assertIn("ТСПУ", d["detail"])
        self.assertIn("норма", d["detail"])
        self.assertIn("nc -zv", d["detail"])
        self.assertIn("полный тест", d["detail"])

    def test_both_dead(self):
        d = self._diag(False, False)
        self.assertEqual(d["legs"], {"hop": "fail", "direct": "fail"})
        self.assertEqual(d["reason"], "хоп и нода не отвечают")


class TestFullPathV2(unittest.TestCase):
    """check_via_node_full_path v2: лестница + deep_diag в интеграции."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self.hops = [_mk_hop("hop-a")]
        self.nd = _mk_node(via="hop-a")

    class _FakeProc:
        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

        def kill(self):
            pass

    def _run(self, fake_run, popen=None, **kw):
        import chimera.modules.chain_relay as cr
        _popen = popen or (lambda cmd, **k: TestFullPathV2._FakeProc())
        with patch.object(cr, "_find_xray_bin",
                          return_value="/usr/local/bin/xray"), \
             patch.object(cr.subprocess, "Popen", side_effect=_popen), \
             patch.object(cr.subprocess, "run", side_effect=fake_run), \
             patch.object(cr, "_resolve_probe_host_ipv4", lambda: None), \
             patch.object(cr.tempfile, "mkstemp",
                          return_value=(99, "/tmp/relaycheck_test.json")), \
             patch("os.write", lambda *a, **kw: None), \
             patch("os.close", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, **kw: None):
            return cr.check_via_node_full_path(self.nd, self.hops, **kw)

    def test_port80_blocked_chain_alive(self):
        # http-проба 000 (порт 80 резался на exit), https — 204 → ok
        def fake_run(cmd, **kw):
            url = cmd[-1]
            if url.startswith("http://"):
                return types.SimpleNamespace(returncode=0,
                                             stdout="000 20.0", stderr="")
            if url == "https://cp.cloudflare.com/generate_204":
                return types.SimpleNamespace(returncode=0,
                                             stdout="204 0.30", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        res = self._run(fake_run)
        self.assertTrue(res["ok"], res)
        self.assertAlmostEqual(res["ms"], 300.0, delta=1)
        self.assertIn("порт 80", res["detail"])
        self.assertEqual(res["reason"], "цепь жива")

    def test_slow_chain_https_retry_ok(self):
        # живой кейс окт. 2026 (вечер, ~400 мс RTT): P1 (80-й)
        # молчит, P2#1 таймаутит, P2#2 — 204 → цепь жива. Раньше одиночная
        # проба + зафильтрованные DoH-IP давали FAIL «нода не отвечает»
        # при живой цепи (полный тест/ICMP при этом ОК).
        attempts = {"n": 0}

        def fake_run(cmd, **kw):
            url = cmd[-1]
            if url.startswith("http://"):
                return types.SimpleNamespace(returncode=0,
                                             stdout="000 20.0", stderr="")
            if url == "https://cp.cloudflare.com/generate_204":
                attempts["n"] += 1
                if attempts["n"] == 1:
                    return types.SimpleNamespace(returncode=0,
                                                 stdout="000 8.0", stderr="")
                return types.SimpleNamespace(returncode=0,
                                             stdout="204 1.50", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        res = self._run(fake_run)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["reason"], "цепь жива")
        self.assertIn("порт 80", res["detail"])
        self.assertEqual(attempts["n"], 2)

    def test_ip_only_dns_broken_not_ok(self):
        # IP-проба проходит, доменные — нет: цепь доходит, но реальный
        # трафик (домены) не пойдёт → ok=False с диагнозом DNS
        def fake_run(cmd, **kw):
            url = cmd[-1]
            if "generate_204" in url:
                return types.SimpleNamespace(returncode=0,
                                             stdout="000 6.0", stderr="")
            if url in ("https://1.1.1.1/", "https://8.8.8.8/"):
                return types.SimpleNamespace(returncode=0,
                                             stdout="301 0.5", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        res = self._run(fake_run)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "DNS на exit")
        self.assertIn("домены", res["detail"])
        # диагностика ног не нужна — и не запускалась
        self.assertEqual(res["legs"], {})

    def test_dead_chain_deep_diag_runs(self):
        # все пробы молчат → deep_diag поднимает ещё 2 xray (хоп / нода)
        popen_calls = []

        def fake_run(cmd, **kw):
            return types.SimpleNamespace(returncode=0, stdout="000 20.0",
                                         stderr="")

        def fake_popen(cmd, **k):
            popen_calls.append(cmd)
            return TestFullPathV2._FakeProc()

        res = self._run(fake_run, popen=fake_popen)
        self.assertFalse(res["ok"])
        self.assertEqual(len(popen_calls), 3)     # main + hop-leg + direct-leg
        self.assertEqual(res["legs"], {"hop": "fail", "direct": "fail"})
        self.assertEqual(res["reason"], "хоп и нода не отвечают")
        self.assertIn("не отвечают", res["detail"])

    def test_dead_chain_deep_diag_off(self):
        # deep_diag=False (HM/балансер) — один xray, без диагностики ног
        popen_calls = []

        def fake_run(cmd, **kw):
            return types.SimpleNamespace(returncode=0, stdout="000 20.0",
                                         stderr="")

        def fake_popen(cmd, **k):
            popen_calls.append(cmd)
            return TestFullPathV2._FakeProc()

        res = self._run(fake_run, popen=fake_popen, deep_diag=False)
        self.assertFalse(res["ok"])
        self.assertEqual(len(popen_calls), 1)
        self.assertEqual(res["legs"], {})
        self.assertEqual(res["reason"], "цепь не отвечает")

    def test_legacy_204_contract_unchanged(self):
        # обычный живой путь: те же поля, что и раньше (HM/меню/шаг 11)
        def fake_run(cmd, **kw):
            url = cmd[-1]
            if "generate_204" in url:
                return types.SimpleNamespace(returncode=0,
                                             stdout="204 0.25", stderr="")
            if "api.ipify.org" in url:
                return types.SimpleNamespace(returncode=0,
                                             stdout="203.0.113.77\n", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        res = self._run(fake_run, want_ip=True)
        self.assertTrue(res["ok"])
        self.assertEqual(res["exit_ip"], "203.0.113.77")
        self.assertAlmostEqual(res["ms"], 250.0, delta=1)
        self.assertEqual(res["speed_mbps"], 0.0)
        self.assertIn("цепочка жива", res["detail"])


# ══════════════════════════════════════════════════════════════════════════════
#  check_node_full_path / node_has_reality_creds — полный зонд ПРЯМОЙ ноды.
#  Живой кейс окт. 2026 №3: голый TCP-ping от HM/балансера/диагностики
#  входной ноды пишется на chimera-exit-ноде как «REALITY: processed invalid
#  connection» → fail2ban xray-reality + DPI-detector цели банят мониторящий
#  IP → ложный DOWN живой ноды. Полный зонд (валидный хендшейк с ключами
#  из state.json) баном не считается.
# ══════════════════════════════════════════════════════════════════════════════
class TestNodeFullPathDirect(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_node_has_reality_creds(self):
        from chimera.modules.chain_relay import node_has_reality_creds
        self.assertTrue(node_has_reality_creds(_mk_node()))
        self.assertFalse(node_has_reality_creds(None))
        self.assertFalse(node_has_reality_creds({}))
        nd = _mk_node(); nd["uuid"] = ""
        self.assertFalse(node_has_reality_creds(nd))
        nd = _mk_node(); nd["pubkey"] = ""
        self.assertFalse(node_has_reality_creds(nd))
        nd = _mk_node(); nd["proto"] = "tcp"
        self.assertFalse(node_has_reality_creds(nd))
        nd = _mk_node(); del nd["host"]
        self.assertFalse(node_has_reality_creds(nd))

    def test_no_host_is_infra(self):
        from chimera.modules.chain_relay import check_node_full_path
        res = check_node_full_path({"port": 443})
        self.assertFalse(res["ok"])
        self.assertTrue(res["infra"])

    def test_no_xray_binary_is_infra(self):
        import chimera.modules.chain_relay as cr
        with patch.object(cr, "_find_xray_bin", return_value=None):
            res = cr.check_node_full_path(_mk_node())
        self.assertFalse(res["ok"])
        self.assertTrue(res["infra"])
        self.assertEqual(res["reason"], "нет xray")

    def test_direct_node_ok_not_infra(self):
        """Живая нода: лестница проб прошла → ok=True, infra=False."""
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
            if "generate_204" in " ".join(map(str, cmd)):
                return types.SimpleNamespace(returncode=0,
                                             stdout="204 0.31", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch.object(cr, "_find_xray_bin",
                          return_value="/usr/local/bin/xray"), \
             patch.object(cr.subprocess, "Popen", return_value=_FakeProc()), \
             patch.object(cr.subprocess, "run", side_effect=fake_run), \
             patch.object(cr, "_resolve_probe_host_ipv4", lambda: None), \
             patch.object(cr.tempfile, "mkstemp",
                          return_value=(99, "/tmp/relaycheck_test.json")), \
             patch("os.write", lambda *a, **kw: None), \
             patch("os.close", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, **kw: None):
            res = cr.check_node_full_path(_mk_node())
        self.assertTrue(res["ok"], res)
        self.assertFalse(res["infra"])
        self.assertAlmostEqual(res["ms"], 310.0, delta=1.0)   # 0.31 c → мс

    def test_want_ip_kwarg_and_exit_ip(self):
        """want_ip=True → ipify-проба через временный socks, IP в exit_ip.

        Регрессия кейса окт.2026 №8: exit_switch_watcher звал прямой зонд
        с want_ip=True, которого у check_node_full_path не было (был
        только у via-варианта) → TypeError «unexpected keyword argument»
        на живой ноде, exit_ip_change не работал.
        """
        import types as _types
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
            joined = " ".join(map(str, cmd))
            if "generate_204" in joined:
                return _types.SimpleNamespace(returncode=0,
                                              stdout="204 0.29", stderr="")
            if "api.ipify.org" in joined:
                return _types.SimpleNamespace(returncode=0,
                                              stdout="203.0.113.77\n", stderr="")
            return _types.SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch.object(cr, "_find_xray_bin",
                          return_value="/usr/local/bin/xray"), \
             patch.object(cr.subprocess, "Popen", return_value=_FakeProc()), \
             patch.object(cr.subprocess, "run", side_effect=fake_run), \
             patch.object(cr, "_resolve_probe_host_ipv4", lambda: None), \
             patch.object(cr.tempfile, "mkstemp",
                          return_value=(99, "/tmp/relaycheck_test.json")), \
             patch("os.write", lambda *a, **kw: None), \
             patch("os.close", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, **kw: None):
            res = cr.check_node_full_path(_mk_node(), want_ip=True)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["exit_ip"], "203.0.113.77")

        # want_ip=False (дефолт) → ipify-проба не выполняется, exit_ip пуст
        def fake_run_no_ipify(cmd, **kwargs):
            joined = " ".join(map(str, cmd))
            assert "api.ipify.org" not in joined, \
                "ipify-проба не должна выполняться без want_ip"
            if "generate_204" in joined:
                return _types.SimpleNamespace(returncode=0,
                                              stdout="204 0.29", stderr="")
            return _types.SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch.object(cr, "_find_xray_bin",
                          return_value="/usr/local/bin/xray"), \
             patch.object(cr.subprocess, "Popen", return_value=_FakeProc()), \
             patch.object(cr.subprocess, "run",
                          side_effect=fake_run_no_ipify), \
             patch.object(cr, "_resolve_probe_host_ipv4", lambda: None), \
             patch.object(cr.tempfile, "mkstemp",
                          return_value=(99, "/tmp/relaycheck_test.json")), \
             patch("os.write", lambda *a, **kw: None), \
             patch("os.close", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, **kw: None):
            res2 = cr.check_node_full_path(_mk_node())
        self.assertTrue(res2["ok"], res2)
        self.assertEqual(res2["exit_ip"], "")


class TestHealthMonitorDirectFullPath(unittest.TestCase):
    """HM: прямая REALITY-нода с ключами → полный зонд, не TCP-пинг
    (анти-DPI, кейс окт. 2026 №3); сбой механизма → TCP-fallback."""

    def setUp(self):
        core = _setup_core_in_sysmodules()
        self._tmp = tempfile.TemporaryDirectory()
        core.STATE_FILE = Path(self._tmp.name) / "state.json"
        core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [_mk_node("de.example.com")],
            "relay_hops": [],
        }))
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

    def test_direct_reality_node_full_path_not_tcp(self):
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        calls = []

        def fake_fp(nd, **kw):
            calls.append("fp:" + nd["host"])
            return {"ok": True, "ms": 321.0, "detail": "нода жива",
                    "infra": False}

        orig_fp = cr.check_node_full_path
        cr.check_node_full_path = fake_fp
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 5.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path = orig_fp
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        self.assertTrue(by_host["de.example.com"]["up"])
        self.assertEqual(by_host["de.example.com"]["ms"], 321.0)
        self.assertIn("fp:de.example.com", calls)
        self.assertNotIn("tcp:de.example.com", calls)

    def test_direct_node_infra_falls_back_tcp(self):
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        calls = []

        def fake_fp(nd, **kw):
            calls.append("fp:" + nd["host"])
            return {"ok": False, "ms": 0.0, "reason": "нет xray",
                    "infra": True}

        orig_fp = cr.check_node_full_path
        cr.check_node_full_path = fake_fp
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 7.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path = orig_fp
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        self.assertTrue(by_host["de.example.com"]["up"])
        self.assertEqual(by_host["de.example.com"]["ms"], 7.0)
        self.assertEqual(calls, ["fp:de.example.com", "tcp:de.example.com"])

    def test_direct_node_without_creds_uses_tcp(self):
        from chimera.modules import node_health_monitor as nhm
        import chimera.modules.chain_relay as cr
        st = json.loads(self._nhm.STATE_FILE.read_text())
        st["chain_nodes"] = [{k: v for k, v in st["chain_nodes"][0].items()
                              if k not in ("uuid", "pubkey", "shortid")}]
        self._nhm.STATE_FILE.write_text(json.dumps(st))
        calls = []
        orig_fp = cr.check_node_full_path
        cr.check_node_full_path = lambda nd, **kw: (
            calls.append("fp:" + nd["host"]) or
            {"ok": True, "ms": 1.0, "infra": False})
        orig_tcp = nhm._tcp_ping
        nhm._tcp_ping = lambda h, p: (calls.append("tcp:" + h) or (True, 9.0))
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path = orig_fp
            nhm._tcp_ping = orig_tcp

        by_host = {r["host"]: r for r in results}
        self.assertTrue(by_host["de.example.com"]["up"])
        self.assertEqual(by_host["de.example.com"]["ms"], 9.0)
        self.assertEqual(calls, ["tcp:de.example.com"])


# ══════════════════════════════════════════════════════════════════════════════
#  check_via_node_full_path.infra + check_node_full_path via-strip.
#  Живой кейс окт. 2026 №4: [T]-пинг via-ноды (ee via hop-fi) вечно писал
#  «нода не отвечает» при живой цепочке 171 мс — прямой зонд строил outbound
#  с sockopt.dialerProxy=hop-fi во временном конфиге БЕЗ хоп-outbound:
#  xray не может набрать несуществующий прокси → все HTTP-пробы 000.
#  Фикс: (а) вызывающий код гоняет via-ноду через check_via_node_full_path
#  (цепочка), (б) check_node_full_path вырезает via из зонда, (в) у
#  via-зонда появился infra-флаг (сбой механизма ≠ вердикт ноде).
# ══════════════════════════════════════════════════════════════════════════════
class TestViaProbeInfraAndViaStrip(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_via_probe_without_via_is_infra(self):
        import chimera.modules.chain_relay as cr
        res = cr.check_via_node_full_path(_mk_node(via=""), [_mk_hop("hop-a")])
        self.assertFalse(res["ok"])
        self.assertTrue(res["infra"])
        self.assertEqual(res["reason"], "via не задан")

    def test_via_probe_disabled_hop_is_infra(self):
        import chimera.modules.chain_relay as cr
        res = cr.check_via_node_full_path(
            _mk_node(via="hop-a"), [_mk_hop("hop-a", enabled=False)])
        self.assertFalse(res["ok"])
        self.assertTrue(res["infra"])   # хоп выключен — механизм, не вердикт
        self.assertEqual(res["reason"], "via не задан")

    def test_via_probe_broken_chain_is_infra(self):
        import chimera.modules.chain_relay as cr
        # цикл hop-a → hop-b → hop-a: тег есть и включён, цепочка битая
        hops = [_mk_hop("hop-a", via="hop-b"), _mk_hop("hop-b", via="hop-a")]
        res = cr.check_via_node_full_path(_mk_node(via="hop-a"), hops)
        self.assertFalse(res["ok"])
        self.assertTrue(res["infra"])
        self.assertEqual(res["reason"], "битая via")

    def test_via_probe_no_xray_is_infra(self):
        import chimera.modules.chain_relay as cr
        with patch.object(cr, "_find_xray_bin", return_value=None):
            res = cr.check_via_node_full_path(
                _mk_node(via="hop-a"), [_mk_hop("hop-a")])
        self.assertFalse(res["ok"])
        self.assertTrue(res["infra"])
        self.assertEqual(res["reason"], "нет xray")

    def test_check_node_full_path_strips_via(self):
        """Прямой зонд обязан вырезать via: dialerProxy во временном
        конфиге указывал бы на несуществующий хоп-outbound (кейс №4)."""
        import chimera.modules.chain_relay as cr

        captured = {}

        class _FakeClient:
            def __init__(self, cfg, xbin):
                captured["cfg"] = cfg

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            start_error = "fake-start-error"

            def alive(self):
                return False

            def err_tail(self, n=200):
                return ""

        nd = _mk_node(via="hop-a")
        with patch.object(cr, "_find_xray_bin",
                          return_value="/usr/local/bin/xray"), \
             patch.object(cr, "_TempXrayClient", _FakeClient):
            res = cr.check_node_full_path(nd)
        # start_error → infra=True (механизм), но конфиг уже построен —
        # проверяем форму outbound-а зонда
        self.assertTrue(res["infra"])
        ob = captured["cfg"]["outbounds"][0]
        sockopt = ob.get("streamSettings", {}).get("sockopt", {})
        self.assertNotIn("dialerProxy", sockopt)     # ← ядро регрессии №4
        self.assertEqual(ob["settings"]["vnext"][0]["address"],
                         "ee.example.com")
        self.assertEqual(ob["tag"], "exit-check")
        # исходный nd вызывающего кода не мутирован
        self.assertEqual(nd.get("via"), "hop-a")


# ══════════════════════════════════════════════════════════════════════════════
#  icmp_rtt / fmt_icmp_rtt — вторая колонка (RTT, чистая сеть) в [T]/HM.
#  Живой кейс окт. 2026 №6: после перевода мониторинга на полные зонды
#  (№3) цифры выросли в ~3 раза — юзер увидел «пинг увеличился». RTT-колонка
#  рядом даёт эталон чистой сети. ICMP — не бан-фуд (не трогает REALITY-порт),
#  информационная: ok=False (фильтруется) НЕ меняет статус ноды.
# ══════════════════════════════════════════════════════════════════════════════
class TestIcmpRtt(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def _run_stdout(self, stdout):
        """icmp_rtt с замоканным subprocess.run (stdout ping-а)."""
        import chimera.modules.chain_relay as cr
        fake = MagicMock()
        fake.stdout = stdout
        with patch.object(cr.subprocess, "run", return_value=fake):
            return cr.icmp_rtt("node.example.com")

    def test_ok_iputils(self):
        r = self._run_stdout(
            "PING node (1.2.3.4) 56(84) bytes of data.\n"
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=58 time=43.1 ms\n"
            "4 packets transmitted, 4 received, 0% packet loss, time 704ms\n"
            "rtt min/avg/max/mdev = 43.159/43.442/43.652/0.246 ms\n")
        self.assertTrue(r["ok"])
        self.assertAlmostEqual(r["avg"], 43.442)
        self.assertAlmostEqual(r["min"], 43.159)
        self.assertAlmostEqual(r["max"], 43.652)
        self.assertEqual(r["loss"], 0)

    def test_ok_round_trip_form(self):
        r = self._run_stdout(
            "3 packets transmitted, 3 received, 0% packet loss\n"
            "round-trip min/avg/max/stddev = 27.1/27.4/27.9/0.3 ms\n")
        self.assertTrue(r["ok"])
        self.assertAlmostEqual(r["avg"], 27.4)

    def test_ok_busybox_sent_received(self):
        r = self._run_stdout(
            "4 sent, 4 received, 0% loss\n"
            "rtt min/avg/max/mdev = 29.0/29.2/29.5/0.2 ms\n")
        self.assertTrue(r["ok"])
        self.assertAlmostEqual(r["avg"], 29.2)

    def test_partial_loss_still_ok(self):
        r = self._run_stdout(
            "4 packets transmitted, 2 received, 50% packet loss\n"
            "rtt min/avg/max/mdev = 43.0/44.0/45.0/1.0 ms\n")
        self.assertTrue(r["ok"])
        self.assertEqual(r["loss"], 50)

    def test_all_lost_not_ok(self):
        r = self._run_stdout(
            "4 packets transmitted, 0 received, 100% packet loss\n")
        self.assertFalse(r["ok"])
        self.assertEqual(r["err"], "ICMP не отвечает/фильтруется")
        self.assertEqual(r["loss"], 100)

    def test_received_without_rtt_line_not_ok(self):
        r = self._run_stdout("3 packets transmitted, 3 received\n")
        self.assertFalse(r["ok"])
        self.assertEqual(r["err"], "rtt-строка не найдена")

    def test_run_exception_not_ok(self):
        import chimera.modules.chain_relay as cr
        with patch.object(cr.subprocess, "run",
                          side_effect=RuntimeError("sandbox")):
            r = cr.icmp_rtt("node.example.com")
        self.assertFalse(r["ok"])
        self.assertIn("RuntimeError", r["err"])

    def test_ping_missing_not_ok(self):
        import chimera.modules.chain_relay as cr
        with patch.object(cr.subprocess, "run",
                          side_effect=FileNotFoundError("no ping")):
            r = cr.icmp_rtt("node.example.com")
        self.assertFalse(r["ok"])
        self.assertEqual(r["err"], "ping не установлен")

    def test_empty_host_not_ok(self):
        import chimera.modules.chain_relay as cr
        r = cr.icmp_rtt("")
        self.assertFalse(r["ok"])
        self.assertEqual(r["err"], "нет host")

    def test_fmt_ok(self):
        import chimera.modules.chain_relay as cr
        self.assertEqual(cr.fmt_icmp_rtt({"ok": True, "avg": 43.44}),
                         "43 мс")

    def test_fmt_not_ok_dash(self):
        import chimera.modules.chain_relay as cr
        self.assertEqual(cr.fmt_icmp_rtt({"ok": False}), "-")
        self.assertEqual(cr.fmt_icmp_rtt({}), "-")
        self.assertEqual(cr.fmt_icmp_rtt(None), "-")


# ══════════════════════════════════════════════════════════════════════════════
#  HM + RTT: rtt попадает в state/results/лог, НИКОГДА не влияет на up/DOWN
#  (инфо-колонка; фильтруемый ICMP → None → «—» в UI).
# ══════════════════════════════════════════════════════════════════════════════
class TestHealthMonitorRtt(unittest.TestCase):
    """RTT (ICMP) в check_nodes_once: state/results/лог; DOWN при живом
    RTT — «сеть жива, туннеля нет»; rtt=None не меняет статус."""

    def setUp(self):
        core = _setup_core_in_sysmodules()
        self._tmp = tempfile.TemporaryDirectory()
        core.STATE_FILE = Path(self._tmp.name) / "state.json"
        core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [_mk_node("de.example.com")],
            "relay_hops": [],
        }))
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

    def test_rtt_in_state_results_and_log(self):
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        orig_fp, orig_icmp = cr.check_node_full_path, cr.icmp_rtt
        cr.check_node_full_path = lambda nd, **kw: {
            "ok": True, "ms": 321.0, "infra": False, "detail": "нода жива"}
        cr.icmp_rtt = lambda host, **kw: {
            "ok": True, "avg": 43.2, "min": 43.0, "max": 43.9, "loss": 0}
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path, cr.icmp_rtt = orig_fp, orig_icmp
        self.assertEqual(results[0]["rtt"], 43.2)
        st = json.loads(self._nhm.HEALTH_STATE.read_text())
        self.assertEqual(st["de.example.com:443"]["rtt"], 43.2)
        log = self._nhm.HEALTH_LOG.read_text()
        self.assertIn("RTT 43ms", log)

    def test_icmp_filtered_rtt_none_up_unchanged(self):
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        orig_fp, orig_icmp = cr.check_node_full_path, cr.icmp_rtt
        cr.check_node_full_path = lambda nd, **kw: {
            "ok": True, "ms": 321.0, "infra": False}
        cr.icmp_rtt = lambda host, **kw: {
            "ok": False, "err": "ICMP не отвечает/фильтруется"}
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path, cr.icmp_rtt = orig_fp, orig_icmp
        self.assertTrue(results[0]["up"])
        self.assertEqual(results[0]["ms"], 321.0)
        self.assertIsNone(results[0]["rtt"])
        st = json.loads(self._nhm.HEALTH_STATE.read_text())
        self.assertIsNone(st["de.example.com:443"]["rtt"])
        log = self._nhm.HEALTH_LOG.read_text()
        self.assertIn("RTT -", log)

    def test_down_with_live_rtt_logged(self):
        """DOWN при живом RTT — сразу виден класс отказа («сеть есть,
        туннеля нет»): лог несёт оба числа."""
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        orig_fp, orig_icmp = cr.check_node_full_path, cr.icmp_rtt
        cr.check_node_full_path = lambda nd, **kw: {
            "ok": False, "ms": 0.0, "infra": False,
            "reason": "нода не отвечает"}
        cr.icmp_rtt = lambda host, **kw: {
            "ok": True, "avg": 27.0, "loss": 0}
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_node_full_path, cr.icmp_rtt = orig_fp, orig_icmp
        self.assertFalse(results[0]["up"])
        self.assertEqual(results[0]["rtt"], 27.0)
        log = self._nhm.HEALTH_LOG.read_text()
        self.assertIn("DOWN (RTT 27ms)", log)

    def test_via_node_rtt_not_verdict(self):
        """via-нода (ee через хоп): вердикт по full-path через цепочку;
        RTT — прямой ICMP до хоста ноды (инфо): при DOWN с живым RTT
        статус остаётся DOWN — RTT его не перекрывает."""
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        st = json.loads(self._nhm.STATE_FILE.read_text())
        st["chain_nodes"] = [_mk_node("ee.example.com", via="hop-fi")]
        st["relay_hops"] = [_mk_hop("hop-fi", host="fi.example.com")]
        self._nhm.STATE_FILE.write_text(json.dumps(st))
        orig_via, orig_icmp = cr.check_via_node_full_path, cr.icmp_rtt
        cr.check_via_node_full_path = lambda nd, hops, **kw: {
            "ok": False, "ms": 0.0, "infra": False,
            "reason": "нода не отвечает", "detail": "все HTTP-пробы 000"}
        cr.icmp_rtt = lambda host, **kw: {"ok": True, "avg": 27.0}
        try:
            results = nhm.check_nodes_once()
        finally:
            cr.check_via_node_full_path, cr.icmp_rtt = orig_via, orig_icmp
        self.assertFalse(results[0]["up"])
        self.assertEqual(results[0]["rtt"], 27.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
