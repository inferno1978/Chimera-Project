#!/usr/bin/env python3
"""
tests/test_b4_route_addon.py
───────────────────────────────────────────────────────────────────────────────
Тесты для chimera/modules/b4_route_addon.py — терминатора эскалации
YouTube (socks-туннель Xray → exit-каскад).

Покрывает:
  1. _b4r_apply_to_xray — socks-inbound + правило ПЕРВЫМ в routing.rules;
     идемпотентность (повторный apply не дублирует); balancerTag для
     балансёра (прецедент tproxy-telemt), outboundTag для ноды.
  2. _b4r_apply_to_xray — неизвестная цель → отказ БЕЗ записи конфига
     (Xray падает с unknown outbound tag).
  3. _b4r_remove_from_xray — чистка inbound + rule (дважды — идемпотентно).
  4. _b4r_load_state / _b4r_save_state — дефолты + валидация (порт,
     цель), roundtrip.
  5. restore_b4_route_if_needed — re-apply при «включено, а патча нет»;
     no-op при выключенном state.
  6. b4-сторона (mock _b4_rest_request): self-healing создания сета,
     синхронизация upstream.port, batch-set-enabled, ensure эскалации.
  7. B4_SET_TEMPLATE — чистый routing proxy, geoip google, без DPI-трюков
     и без публичных IP-литералов (нулевая IP-политика leak_guard).
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
    """Регистрирует фейковый chimera._core (как test_youtube_route:
    exec в __dict__ фейкового модуля — мутации видны функциям ядра)."""
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


def _make_xray_config() -> dict:
    """Минимальный прод-подобный конфиг Xray каскада (4 exit-ноды +
    балансёр + ru_subnets + youtube_via_ru + catch-all)."""
    return {
        "inbounds": [
            {"protocol": "vless", "tag": "inbound-vless", "listen": "::",
             "port": 443, "settings": {"clients": []}},
            {"protocol": "dokodemo-door", "tag": "tproxy-telemt",
             "listen": "127.0.0.1", "port": 10811},
        ],
        "outbounds": [
            {"protocol": "vless", "tag": f"chain-exit-{i}"} for i in (1, 2, 3, 4)
        ] + [
            {"protocol": "blackhole", "tag": "BLOCK"},
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [
                {"tag": "chain-balancer",
                 "selector": [f"chain-exit-{i}" for i in (1, 2, 3, 4)]},
            ],
            "rules": [
                {"type": "field", "ip": ["10.0.0.0/8"],
                 "outboundTag": "direct", "comment": "ru_subnets_ripe"},
                {"type": "field", "domain": ["geosite:youtube"],
                 "outboundTag": "direct", "comment": "youtube_via_ru"},
                {"type": "field", "inboundTag": ["tproxy-telemt"],
                 "balancerTag": "chain-balancer"},
                {"type": "field", "network": "tcp,udp",
                 "outboundTag": "direct"},
            ],
        },
    }


class _XrayPatchMixin:
    """Подготовка: фейковый _core + tmp-конфиг + патчи путей/рестарта."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self.core = _setup_core_in_sysmodules()
        # xray-рестарт — в заглушки (не трогаем systemd).
        self.core._xray_safe_restart = MagicMock(return_value=True)
        self.core._run = MagicMock(
            return_value=subprocess.CompletedProcess([], 0, "", ""))
        self.core._set_config_owner = MagicMock()
        self.core.STATE_FILE = self._tmpdir / "state.json"
        self.core.CONFIG_DIR = self._tmpdir
        import importlib
        from chimera.modules import b4_route_addon as mod
        importlib.reload(mod)
        self.mod = mod
        self.mod._core_module = lambda: self.core

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_cfg(self, cfg=None):
        self._cfg_path.write_text(json.dumps(cfg or _make_xray_config()))

    def _read_cfg(self) -> dict:
        return json.loads(self._cfg_path.read_text())


class TestApplyToXray(_XrayPatchMixin, unittest.TestCase):
    """_b4r_apply_to_xray: inbound + правило ПЕРВЫМ, идемпотентность."""

    def test_apply_balancer_rule_first_with_balanertag(self):
        self._write_cfg()
        ok = self.mod._b4r_apply_to_xray("balancer", 10810)
        self.assertTrue(ok)
        cfg = self._read_cfg()
        # inbound на месте: socks / 127.0.0.1 / noauth / udp off
        inbound = next(i for i in cfg["inbounds"]
                       if i.get("tag") == self.mod.B4R_INBOUND_TAG)
        self.assertEqual(inbound["protocol"], "socks")
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 10810)
        self.assertEqual(inbound["settings"]["auth"], "noauth")
        self.assertIs(inbound["settings"]["udp"], False)
        # правило ПЕРВОЕ (до ru_subnets и youtube_via_ru — иначе петля)
        rule = cfg["routing"]["rules"][0]
        self.assertEqual(rule["comment"], self.mod.B4R_RULE_COMMENT)
        self.assertEqual(rule["inboundTag"], [self.mod.B4R_INBOUND_TAG])
        self.assertEqual(rule["balancerTag"], "chain-balancer")
        self.assertNotIn("outboundTag", rule)
        # youtube_via_ru правило осталось ниже
        self.assertIn("youtube_via_ru",
                      [r.get("comment") for r in cfg["routing"]["rules"]])

    def test_apply_specific_node_uses_outboundtag(self):
        self._write_cfg()
        ok = self.mod._b4r_apply_to_xray("chain-exit-2", 10810)
        self.assertTrue(ok)
        rule = self._read_cfg()["routing"]["rules"][0]
        self.assertEqual(rule["outboundTag"], "chain-exit-2")
        self.assertNotIn("balancerTag", rule)

    def test_apply_idempotent_no_duplicates(self):
        self._write_cfg()
        self.mod._b4r_apply_to_xray("balancer", 10810)
        self.mod._b4r_apply_to_xray("balancer", 10810)
        cfg = self._read_cfg()
        rules = [r for r in cfg["routing"]["rules"]
                 if r.get("comment") == self.mod.B4R_RULE_COMMENT]
        inbounds = [i for i in cfg["inbounds"]
                    if i.get("tag") == self.mod.B4R_INBOUND_TAG]
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(inbounds), 1)

    def test_apply_unknown_node_refused_without_write(self):
        self._write_cfg()
        before = self._cfg_path.read_text()
        ok = self.mod._b4r_apply_to_xray("chain-exit-9", 10810)
        self.assertFalse(ok)
        self.assertEqual(self._cfg_path.read_text(), before)  # конфиг не тронут

    def test_apply_invalid_target_format_refused(self):
        self._write_cfg()
        self.assertFalse(self.mod._b4r_apply_to_xray("nonsense", 10810))


class TestRemoveFromXray(_XrayPatchMixin, unittest.TestCase):
    """_b4r_remove_from_xray: чистка inbound + rule."""

    def test_remove_after_apply(self):
        self._write_cfg()
        self.mod._b4r_apply_to_xray("balancer", 10810)
        self.assertTrue(self.mod._b4r_remove_from_xray())
        cfg = self._read_cfg()
        self.assertNotIn(self.mod.B4R_RULE_COMMENT,
                         [r.get("comment") for r in cfg["routing"]["rules"]])
        self.assertNotIn(self.mod.B4R_INBOUND_TAG,
                         [i.get("tag") for i in cfg["inbounds"]])
        # соседний tproxy-telemt не тронут
        self.assertIn("tproxy-telemt",
                      [i.get("tag") for i in cfg["inbounds"]])
        # повторный remove — тоже успех (идемпотентность)
        self.assertTrue(self.mod._b4r_remove_from_xray())


class TestState(_XrayPatchMixin, unittest.TestCase):
    """_b4r_load_state / _b4r_save_state: дефолты, валидация, roundtrip."""

    def test_defaults_when_no_state(self):
        st = self.mod._b4r_load_state()
        self.assertIs(st["b4_route_enabled"], False)
        self.assertEqual(st["b4_route_target"], "balancer")
        self.assertEqual(st["b4_route_port"], 10810)
        self.assertEqual(st["b4_route_set"], "Youtube-Route-v1")
        self.assertEqual(st["b4_route_front_set"], "Youtube-Heavy-v1")

    def test_save_load_roundtrip_and_validation(self):
        self.mod._b4r_save_state(b4_route_enabled=True,
                                 b4_route_target="chain-exit-3",
                                 b4_route_port=10812)
        st = self.mod._b4r_load_state()
        self.assertTrue(st["b4_route_enabled"])
        self.assertEqual(st["b4_route_target"], "chain-exit-3")
        self.assertEqual(st["b4_route_port"], 10812)
        # инвалидные значения схлопываются к дефолтам
        self.mod._b4r_save_state(b4_route_target="junk", b4_route_port=1)
        st = self.mod._b4r_load_state()
        self.assertEqual(st["b4_route_target"], "balancer")
        self.assertEqual(st["b4_route_port"], 10810)


class TestRestore(_XrayPatchMixin, unittest.TestCase):
    """restore_b4_route_if_needed: re-apply после regenerate."""

    def test_restore_when_enabled_and_patch_missing(self):
        self._write_cfg()
        self.mod._b4r_save_state(b4_route_enabled=True,
                                 b4_route_target="balancer")
        self.assertTrue(self.mod.restore_b4_route_if_needed())
        cfg = self._read_cfg()
        self.assertEqual(cfg["routing"]["rules"][0]["comment"],
                         self.mod.B4R_RULE_COMMENT)

    def test_noop_when_disabled(self):
        self._write_cfg()
        self.mod._b4r_save_state(b4_route_enabled=False)
        self.assertFalse(self.mod.restore_b4_route_if_needed())
        self.assertNotIn(self.mod.B4R_RULE_COMMENT,
                         [r.get("comment")
                          for r in self._read_cfg()["routing"]["rules"]])

    def test_noop_when_patch_in_place(self):
        self._write_cfg()
        self.mod._b4r_apply_to_xray("balancer", 10810)
        self.mod._b4r_save_state(b4_route_enabled=True,
                                 b4_route_target="balancer",
                                 b4_route_port=10810)
        with patch.object(self.mod, "_b4r_apply_to_xray",
                          wraps=self.mod._b4r_apply_to_xray) as spied:
            self.assertFalse(self.mod.restore_b4_route_if_needed())
            spied.assert_not_called()


class TestB4RestSide(_XrayPatchMixin, unittest.TestCase):
    """b4-сторона через REST (mock _b4_rest_request в youtube_b4)."""

    def _fake_rest_routes(self, sets_state):
        """Роутер mock-ответов: список сетов / создание / PUT / batch.

        GET /api/sets отвечает ПЛОСКИМ МАССИВОМ — как реальный b4
        (регресс: первый деплой споткнулся ровно об это, см. changelog).
        """
        def router(method, path, payload=None, **kw):
            if method == "GET" and path == "/api/sets":
                return (200, [
                    {"id": s["id"], "name": s["name"], "enabled": s["enabled"]}
                    for s in sets_state])
            m = (method == "GET"
                 and path.startswith("/api/sets/")
                 and not path.endswith("/batch-set-enabled"))
            if m:
                sid = path.rsplit("/", 1)[1]
                for s in sets_state:
                    if s["id"] == sid:
                        return (200, dict(s))
                return (404, {"error": "not found"})
            if method == "POST" and path == "/api/sets":
                payload = dict(payload or {})
                payload["id"] = "new-id"
                payload["enabled"] = False
                sets_state.append(payload)
                return (200, payload)
            if method == "POST" and path == "/api/sets/batch-set-enabled":
                for s in sets_state:
                    if s.get("id") in (payload or {}).get("ids", []):
                        s["enabled"] = bool((payload or {}).get("enabled"))
                return (200, {"ok": True})
            if method == "PUT" and path.startswith("/api/sets/"):
                sid = path.rsplit("/", 1)[1]
                for i, s in enumerate(sets_state):
                    if s["id"] == sid:
                        payload = dict(payload or {})
                        payload.setdefault("id", sid)
                        sets_state[i] = payload
                        return (200, payload)
                return (404, {"error": "not found"})
            return (404, {"error": "no route"})
        return router

    def test_ensure_set_creates_from_template_when_missing(self):
        sets_state = []  # сета нет — self-healing через POST
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router):
            s = self.mod._b4r_ensure_b4_set("Youtube-Route-v1", 10810)
        self.assertIsNotNone(s)
        created = sets_state[0]
        self.assertEqual(created["name"], "Youtube-Route-v1")
        self.assertEqual(created["routing"]["mode"], "proxy")
        self.assertEqual(created["routing"]["upstream"]["host"], "127.0.0.1")
        self.assertEqual(created["routing"]["upstream"]["port"], 10810)
        self.assertEqual(created["targets"]["geoip_categories"], ["google"])
        self.assertEqual(created["targets"]["geosite_categories"], ["youtube"])
        self.assertIn("dns.google", created["targets"]["sni_domains"])
        self.assertEqual(created["udp"]["mode"], "off")

    def test_ensure_set_adds_naming_domains_when_missing(self):
        """РЕГРЕСС RU1 (прод 11.11): сет без доменов → CONNECT сырыми IP →
        exit-2/3 не достают сырые Google-IP → туннель мёртв. Ensure обязан
        добавлять geosite:youtube + dns.google, не трогая чужие записи."""
        sets_state = [{
            "id": "route-1", "name": "Youtube-Route-v1", "enabled": False,
            "routing": {"mode": "proxy", "upstream":
                        {"host": "127.0.0.1", "port": 10810}},
            "targets": {"geoip_categories": ["google"],
                        "sni_domains": ["my.custom.example"]},
        }]
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router):
            s = self.mod._b4r_ensure_b4_set("Youtube-Route-v1", 10810)
        self.assertIsNotNone(s)
        t = sets_state[0]["targets"]
        self.assertIn("youtube", t["geosite_categories"])
        # пользовательские домены не тронуты, шаблонные добавлены
        self.assertIn("my.custom.example", t["sni_domains"])
        self.assertIn("dns.google", t["sni_domains"])
        self.assertIn("dns.google.com", t["sni_domains"])
        # идемпотентность: повторный ensure не дублирует
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router) as spy:
            self.mod._b4r_ensure_b4_set("Youtube-Route-v1", 10810)
        puts = [c for c in spy.call_args_list
                if c.args and c.args[0] == "PUT"]
        self.assertEqual(len(puts), 0)  # всё уже на месте — без записи
        self.assertEqual(sets_state[0]["targets"]["sni_domains"].count("dns.google"), 1)

    def test_ensure_set_fixes_port_mismatch(self):
        sets_state = [{
            "id": "route-1", "name": "Youtube-Route-v1", "enabled": False,
            "routing": {"mode": "proxy", "upstream":
                        {"host": "127.0.0.1", "port": 9999}},
            "targets": {"geoip_categories": ["google"]},
        }]
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router):
            self.mod._b4r_ensure_b4_set("Youtube-Route-v1", 10810)
        self.assertEqual(sets_state[0]["routing"]["upstream"]["port"], 10810)

    def test_set_enabled_uses_batch_endpoint(self):
        sets_state = [{"id": "route-1", "name": "Youtube-Route-v1",
                       "enabled": False}]
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router) as spy:
            self.assertTrue(self.mod._b4r_set_enabled("Youtube-Route-v1", True))
        self.assertTrue(sets_state[0]["enabled"])
        calls = [(c.args[0], c.args[1]) for c in spy.call_args_list
                 if c.args and c.args[0] == "POST"]
        self.assertIn(("POST", "/api/sets/batch-set-enabled"), calls)

    def test_ensure_escalation_wires_front_to_route(self):
        sets_state = [
            {"id": "route-1", "name": "Youtube-Route-v1", "enabled": False,
             "escalate": {"to": ""}},
            {"id": "heavy-1", "name": "Youtube-Heavy-v1", "enabled": True,
             "escalate": {"to": ""}},
        ]
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router):
            self.assertTrue(self.mod._b4r_ensure_escalation(
                "Youtube-Heavy-v1", "Youtube-Route-v1"))
        heavy = next(s for s in sets_state if s["name"] == "Youtube-Heavy-v1")
        self.assertEqual(heavy["escalate"]["to"], "route-1")

    def test_escalation_already_wired_is_noop(self):
        sets_state = [
            {"id": "route-1", "name": "Youtube-Route-v1", "enabled": False,
             "escalate": {"to": ""}},
            {"id": "heavy-1", "name": "Youtube-Heavy-v1", "enabled": True,
             "escalate": {"to": "route-1"}},
        ]
        router = self._fake_rest_routes(sets_state)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   side_effect=router) as spy:
            self.assertTrue(self.mod._b4r_ensure_escalation(
                "Youtube-Heavy-v1", "Youtube-Route-v1"))
        puts = [c for c in spy.call_args_list
                if c.args and c.args[0] == "PUT"]
        self.assertEqual(len(puts), 0)  # уже пропісано — без записи

    def test_sets_list_tolerates_array_and_dict_shapes(self):
        """РЕГРЕСС первого деплоя: реальный b4 отвечает ПЛОСКИМ МАССИВОМ
        на GET /api/sets (как ждёт youtube_b4._b4_rest_import_set);
        парсер обязан брать оба формата — массив и dict-обёртку."""
        the_set = {"id": "route-1", "name": "Youtube-Route-v1",
                   "enabled": True}
        for shape in (
            [the_set],                     # плоский массив — живой b4 1.90.0
            {"sets": [the_set]},           # dict-обёртка — толерантность
        ):
            def router(method, path, payload=None, _shape=shape, **kw):
                if method == "GET" and path == "/api/sets":
                    return (200, _shape)
                if method == "GET" and path == "/api/sets/route-1":
                    return (200, dict(the_set))
                return (404, {"error": "no route"})
            with patch("chimera.modules.youtube_b4._b4_rest_request",
                       side_effect=router):
                sets = self.mod._b4r_sets_list()
                self.assertIsNotNone(sets, f"формат не распознан: {type(shape)}")
                self.assertEqual(len(sets), 1)
                found = self.mod._b4r_find_b4_set("Youtube-Route-v1")
                self.assertIsNotNone(found)
                self.assertEqual(found.get("id"), "route-1")
        # REST недоступен → None (не список)
        with patch("chimera.modules.youtube_b4._b4_rest_request",
                   return_value=None):
            self.assertIsNone(self.mod._b4r_sets_list())


class TestTemplate(_XrayPatchMixin, unittest.TestCase):
    """B4_SET_TEMPLATE: политика сета (чистый routing, без трюков, без IP)."""

    def test_template_is_clean_routing_proxy(self):
        t = self.mod.B4_SET_TEMPLATE
        self.assertEqual(t["udp"]["mode"], "off")
        self.assertEqual(t["fragmentation"]["strategy"], "none")
        self.assertIs(t["faking"]["sni"], False)
        self.assertIs(t["routing"]["enabled"], True)
        self.assertEqual(t["routing"]["mode"], "proxy")
        self.assertFalse(t["routing"]["upstream"]["udp"])  # QUIC режется b4
        self.assertIs(t["routing"]["upstream"]["fail_open"], False)
        self.assertIs(t["routing"]["upstream"]["use_domain"], True)
        self.assertEqual(t["targets"]["geoip_categories"], ["google"])
        self.assertNotIn("ip", t["targets"])  # только geoip-категория, без ручных IP
        # Домены именования CONNECT'ов: без них листенер не нюхает SNI
        # (needsSniff = !names.Empty() || setHasDomains) и CONNECT уходит
        # сырым IP — а exit-ноды гетерогенны по сырым Google-IP (RU1, прод).
        self.assertEqual(t["targets"]["geosite_categories"], ["youtube"])
        self.assertEqual(t["targets"]["sni_domains"],
                         ["dns.google", "dns.google.com"])

    def test_template_no_public_ip_literals(self):
        """Нулевая IP-политика leak_guard: в шаблоне нет IP-литералов,
        кроме loopback upstream (127.0.0.1)."""
        import re
        src = json.dumps(self.mod.B4_SET_TEMPLATE)
        ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", src))
        self.assertTrue(ips.issubset({"127.0.0.1"}), f"лишние IP: {ips}")

    def test_rule_builder_balancer_vs_node(self):
        r = self.mod._b4r_build_rule("balancer")
        self.assertEqual(r["balancerTag"], "chain-balancer")
        self.assertNotIn("outboundTag", r)
        r2 = self.mod._b4r_build_rule("chain-exit-4")
        self.assertEqual(r2["outboundTag"], "chain-exit-4")
        self.assertNotIn("balancerTag", r2)


class TestAvailableTargets(_XrayPatchMixin, unittest.TestCase):
    """_b4r_available_targets: динамическое обнаружение живых целей."""

    def test_discovers_nodes_balancers_extras(self):
        cfg = _make_xray_config()
        cfg["outbounds"].append({"protocol": "freedom", "tag": "warp"})
        t = self.mod._b4r_available_targets(cfg)
        self.assertEqual(t["nodes"],
                         ["chain-exit-1", "chain-exit-2",
                          "chain-exit-3", "chain-exit-4"])
        self.assertEqual(t["balancers"], ["chain-balancer"])
        self.assertEqual(t["extra"], ["warp"])


class TestHeal(_XrayPatchMixin, unittest.TestCase):
    """b4_route_heal: починка ip rule после rebuild-гонки b4
    (баг воспроизведён в проде 11.11: снесён lookup-252 при живом
    source-check — SYN на google-IP уходил напрямую в ТСПУ)."""

    RULES_OK = (
        "0:\tfrom all lookup local\n"
        "2:\tfrom all fwmark 0x25efe/0x1027fff iif lo lookup main\n"
        "3:\tfrom all fwmark 0x25efe/0x27fff lookup 252\n"
        "32766:\tfrom all lookup main\n"
    )
    RULES_BROKEN = (
        "0:\tfrom all lookup local\n"
        "2:\tfrom all fwmark 0x25efe/0x1027fff iif lo lookup main\n"
        "32766:\tfrom all lookup main\n"
    )

    def test_heal_noop_when_rule_present(self):
        with patch.object(self.mod, "_b4r_ip_rule_show",
                          return_value=self.RULES_OK), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)) as spy:
            rep = self.mod.b4_route_heal()
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["action"], "none")
        # ни одного мутирующего вызова ip rule add
        for c in spy.call_args_list:
            args = c.args[0] if c.args else c.kwargs.get("args")
            self.assertNotIn("add", args)

    def test_heal_readds_missing_rule_in_b4_form(self):
        ok_run = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(self.mod, "_b4r_ip_rule_show",
                          return_value=self.RULES_BROKEN), \
             patch("subprocess.run", return_value=ok_run) as spy:
            rep = self.mod.b4_route_heal()
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["action"], "re-added")
        # форма ровно как у b4: fwmark 0x25efe/0x27fff lookup 252 priority 3
        # (марка взята из живого source-check, не хардкодом)
        add_calls = [c.args[0] for c in spy.call_args_list
                     if c.args and isinstance(c.args[0], list)
                     and c.args[0][:1] == ["ip"]]
        self.assertTrue(any(
            "add" in a and "0x25efe/0x27fff" in a and "252" in a
            and "3" in a for a in add_calls), add_calls)

    def test_heal_noop_when_routing_absent(self):
        # сет снят целиком: ни source-check, ни lookup — валидное состояние
        with patch.object(self.mod, "_b4r_ip_rule_show",
                          return_value="0:\tfrom all lookup local\n"), \
             patch("subprocess.run") as spy:
            rep = self.mod.b4_route_heal()
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["action"], "routing-absent")
        spy.assert_not_called()

    def test_heal_cron_install_and_remove_idempotent(self):
        crontab = {"cur": "0 3 * * * old-job\n"}
        def fake_run(cmd, **kw):
            class R:
                returncode = 0
                stdout = crontab["cur"]
                stderr = ""
            if cmd[:2] == ["crontab", "-l"]:
                return R()
            if cmd[:1] == ["crontab"]:
                crontab["cur"] = kw.get("input", "")
                return R()
            return R()
            return R()
        with patch("subprocess.run", side_effect=fake_run):
            self.assertTrue(self.mod._b4r_install_heal_cron())
            first = crontab["cur"]
            self.assertIn(self.mod.B4R_HEAL_CRON_MARK, first)
            self.assertIn("b4_route_addon heal --quiet", first)
            self.assertIn("old-job", first)  # чужие записи не тронуты
            # идемпотентность: повторная установка не дублирует
            self.assertTrue(self.mod._b4r_install_heal_cron())
            self.assertEqual(crontab["cur"], first)
            # снятие: маркер и строка уходят, чужие остаются
            self.mod._b4r_uninstall_heal_cron()
            self.assertNotIn(self.mod.B4R_HEAL_CRON_MARK, crontab["cur"])
            self.assertNotIn("b4_route_addon heal", crontab["cur"])
            self.assertIn("old-job", crontab["cur"])

    def test_apply_installs_heal_cron(self):
        """apply ставит heal-cron (баг-обход), remove — снимает."""
        self._write_cfg()
        with patch.object(self.mod, "_b4r_ip_rule_show",
                          return_value=self.RULES_OK), \
             patch.object(self.mod, "_b4r_youtube_ru_ok", return_value=True), \
             patch.object(self.mod, "_b4r_ensure_b4_set",
                          return_value={"id": "x", "routing": {}}), \
             patch.object(self.mod, "_b4r_ensure_escalation", return_value=True), \
             patch.object(self.mod, "_b4r_set_enabled", return_value=True), \
             patch.object(self.mod, "_b4r_probe", return_value={"ok": True}), \
             patch.object(self.mod, "_b4r_install_heal_cron",
                          return_value=True) as inst:
            rep = self.mod.b4_route_apply(target="balancer")
        self.assertTrue(rep["ok"])
        self.assertTrue(rep["heal_cron"])
        inst.assert_called_once()


if __name__ == "__main__":
    unittest.main()
