#!/usr/bin/env python3
"""
tests/test_custom_outbounds.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/custom_outbounds.py.

Покрывает:
  1. base64-декодер (стандартный/urlsafe-алфавит, без паддинга)
  2. _stream_settings — матрица транспортов × security (единый источник
     правды для ссылок и мастера)
  3. Парсеры ссылок: vless:// (REALITY/ws/no-port/no-uuid), vmess://
     (base64-JSON, REALITY, битый b64), trojan:// (TLS по умолчанию),
     ss:// (SIP002 b64, SIP002 plain, legacy full-b64, IPv6, plugin-warn)
  4. JSON-outbound (валидный, полный конфиг, без protocol, вырезка tag)
  5. Валидаторы (host/port/uuid/tag)
  6. _co_suggest_tag — имена ссылок → допустимые теги
  7. State I/O + co_state_tags
  8. _co_apply_to_xray — append в конец, идемпотентность, удаление
     выключенных, удаление последнего entry (known_tags — без него
     осиротевший outbound оставался в конфиге), откат при невалидном
     конфиге, оба конфига, дефолтный outbound не трогаем
  9. restore_custom_outbounds_if_needed — re-apply после «regenerate»
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import custom_outbounds as co


def _ok_run(rc: int = 0, stdout: str = ""):
    return subprocess.CompletedProcess(args=[], returncode=rc,
                                       stdout=stdout, stderr="")


def _mk_cfg(outbounds=None, rules=None) -> dict:
    return {
        "inbounds": [{"protocol": "vless", "tag": "in", "port": 443}],
        "outbounds": outbounds if outbounds is not None else [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {"rules": rules or [
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]},
    }


def _entry(name="friend-1", enabled=True, proto="vless",
           addr="1.2.3.4", port=443, source="link"):
    ob = {
        "protocol": proto,
        "settings": {"vnext": [{"address": addr, "port": port,
                                "users": [{"id": "3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d",
                                           "encryption": "none"}]}]},
        "streamSettings": {"network": "tcp", "security": "reality",
                           "realitySettings": {
                               "show": False, "fingerprint": "chrome",
                               "serverName": "sni.example.com",
                               "publicKey": "P4gDz-wZD90iqSmen-ocScmwB3fIWQqBtfGU_uFa4mA",
                               "shortId": "abcd1234", "spiderX": "/"}},
    }
    return {"name": name, "enabled": enabled, "source": source,
            "outbound": ob,
            "created_at": "2026-11-04 00:00:00",
            "updated_at": "2026-11-04 00:00:00"}


# ══════════════════════════════════════════════════════════════════════════════
#  base64
# ══════════════════════════════════════════════════════════════════════════════

class TestB64Decode(unittest.TestCase):

    def test_standard_with_padding(self):
        import base64
        self.assertEqual(co._b64_decode(base64.b64encode(b"hello")), b"hello")
        # bytes-вход без паддинга (робастность) тоже декодируется
        self.assertEqual(co._b64_decode(b"aGVsbG8"), b"hello")

    def test_urlsafe_no_padding(self):
        # b64 "abc12345" → 11 символов без '='
        raw = "YWJjMTIzNDU2"[:11]
        import base64
        expect = base64.urlsafe_b64decode(raw + "==")
        self.assertEqual(co._b64_decode(raw), expect)

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            co._b64_decode("")

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            co._b64_decode("   ")


# ══════════════════════════════════════════════════════════════════════════════
#  _stream_settings
# ══════════════════════════════════════════════════════════════════════════════

class TestStreamSettings(unittest.TestCase):

    def test_reality_tcp(self):
        ss, w = co._stream_settings({
            "type": "tcp", "security": "reality", "sni": "s.example.com",
            "fp": "firefox", "pbk": "PUBKEY", "sid": "abcd", "spx": "/"})
        self.assertEqual(ss["network"], "tcp")
        self.assertEqual(ss["security"], "reality")
        rs = ss["realitySettings"]
        self.assertEqual(rs["serverName"], "s.example.com")
        self.assertEqual(rs["publicKey"], "PUBKEY")
        self.assertEqual(rs["shortId"], "abcd")
        self.assertEqual(rs["fingerprint"], "firefox")
        self.assertEqual(w, [])

    def test_reality_no_pbk_warns(self):
        _, w = co._stream_settings({"type": "tcp", "security": "reality"})
        self.assertTrue(any("pbk" in x for x in w))

    def test_tls_ws(self):
        ss, w = co._stream_settings({
            "type": "ws", "security": "tls", "sni": "a.b",
            "path": "/ws", "host": "front.b", "alpn": "h2,http/1.1",
            "allowInsecure": "1"})
        self.assertEqual(ss["wsSettings"]["path"], "/ws")
        self.assertEqual(ss["wsSettings"]["headers"]["Host"], "front.b")
        ts = ss["tlsSettings"]
        self.assertEqual(ts["serverName"], "a.b")
        self.assertEqual(ts["alpn"], ["h2", "http/1.1"])
        self.assertTrue(ts["allowInsecure"])
        self.assertEqual(w, [])

    def test_grpc(self):
        ss, _ = co._stream_settings({"type": "grpc", "security": "none",
                                     "serviceName": "svc", "multiMode": "1"})
        self.assertEqual(ss["network"], "grpc")
        g = ss["grpcSettings"]
        self.assertEqual(g["serviceName"], "svc")
        self.assertTrue(g["multiMode"])

    def test_xhttp(self):
        ss, _ = co._stream_settings({"type": "xhttp", "path": "/xh",
                                     "host": "h.b", "mode": "packet"})
        self.assertEqual(ss["xhttpSettings"]["path"], "/xh")
        self.assertEqual(ss["xhttpSettings"]["mode"], "packet")

    def test_tcp_http_header(self):
        ss, _ = co._stream_settings({"type": "tcp", "headerType": "http",
                                     "path": "/hi", "host": "www.b"})
        req = ss["tcpSettings"]["header"]["request"]
        self.assertEqual(req["path"], ["/hi"])
        self.assertEqual(req["headers"]["Host"], ["www.b"])

    def test_unknown_network_falls_back_tcp(self):
        ss, w = co._stream_settings({"type": "quantum", "security": "none"})
        self.assertEqual(ss["network"], "tcp")
        self.assertTrue(any("quantum" in x for x in w))

    def test_raw_alias_tcp(self):
        ss, _ = co._stream_settings({"type": "raw"})
        self.assertEqual(ss["network"], "tcp")

    def test_kcp_maps_mkcp(self):
        ss, _ = co._stream_settings({"type": "kcp", "seed": "s33d",
                                     "headerType": "srtp"})
        self.assertEqual(ss["network"], "mkcp")
        self.assertEqual(ss["kcpSettings"]["seed"], "s33d")
        self.assertEqual(ss["kcpSettings"]["header"]["type"], "srtp")

    def test_none_security_default(self):
        ss, _ = co._stream_settings({"type": "tcp"})
        self.assertEqual(ss["security"], "none")

    def test_httpupgrade(self):
        ss, _ = co._stream_settings({"type": "httpupgrade", "path": "/up",
                                     "host": "u.b"})
        self.assertEqual(ss["httpupgradeSettings"]["host"], "u.b")


# ══════════════════════════════════════════════════════════════════════════════
#  vless://
# ══════════════════════════════════════════════════════════════════════════════

VLESS_REALITY = ("vless://3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d@total-shadows.ru:443"
                 "?encryption=none&flow=xtls-rprx-vision&security=reality"
                 "&sni=total-shadows.ru&fp=firefox"
                 "&pbk=P4gDz-wZD90iqSmen-ocScmwB3fIWQqBtfGU_uFa4mA"
                 "&sid=b6cb7d14cad79e94&type=tcp&spiderX=%2F"
                 "#%D0%94%D1%80%D1%83%D0%B3%20YYY")


class TestParseVless(unittest.TestCase):

    def test_reality_full(self):
        parts = co._parse_vless(VLESS_REALITY)
        self.assertEqual(parts["protocol"], "vless")
        v = parts["settings"]["vnext"][0]
        self.assertEqual(v["address"], "total-shadows.ru")
        self.assertEqual(v["port"], 443)
        u = v["users"][0]
        self.assertEqual(u["id"], "3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d")
        self.assertEqual(u["encryption"], "none")
        self.assertEqual(u["flow"], "xtls-rprx-vision")
        ss = parts["streamSettings"]
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ss["realitySettings"]["publicKey"],
                         "P4gDz-wZD90iqSmen-ocScmwB3fIWQqBtfGU_uFa4mA")
        self.assertEqual(ss["realitySettings"]["shortId"], "b6cb7d14cad79e94")
        self.assertEqual(parts["suggested"], "Друг YYY")

    def test_ws_tls_minimal(self):
        parts = co._parse_vless(
            "vless://3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d@1.2.3.4:8443"
            "?type=ws&path=%2Fws&host=front.example.com&security=tls#node")
        ss = parts["streamSettings"]
        self.assertEqual(ss["network"], "ws")
        self.assertEqual(ss["security"], "tls")
        # конвенция v2rayN/NekoBox: SNI без sni= берётся из host=
        self.assertEqual(ss["tlsSettings"]["serverName"], "front.example.com")
        self.assertEqual(ss["wsSettings"]["headers"]["Host"], "front.example.com")

    def test_no_port_raises(self):
        with self.assertRaises(ValueError):
            co._parse_vless("vless://3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d@host")

    def test_no_uuid_raises(self):
        with self.assertRaises(ValueError):
            co._parse_vless("vless://host:443")

    def test_ipv6_brackets(self):
        parts = co._parse_vless(
            "vless://3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d@[2001:db8:ab80::5]:443?type=tcp")
        self.assertEqual(parts["settings"]["vnext"][0]["address"],
                         "2001:db8:ab80::5")


# ══════════════════════════════════════════════════════════════════════════════
#  vmess://
# ══════════════════════════════════════════════════════════════════════════════

def _vmess_link(obj: dict) -> str:
    import base64
    return "vmess://" + base64.b64encode(
        json.dumps(obj).encode()).decode()


class TestParseVmess(unittest.TestCase):

    def test_standard_ws_tls(self):
        parts = co._parse_vmess(_vmess_link({
            "v": "2", "ps": "мой друг", "add": "vm.example.com", "port": "443",
            "id": "3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d", "aid": "0",
            "scy": "auto", "net": "ws", "type": "none",
            "host": "front.example.com", "path": "/vm", "tls": "tls",
            "sni": "vm.example.com"}))
        self.assertEqual(parts["protocol"], "vmess")
        v = parts["settings"]["vnext"][0]
        self.assertEqual(v["address"], "vm.example.com")
        self.assertEqual(v["port"], 443)
        u = v["users"][0]
        self.assertEqual(u["alterId"], 0)
        self.assertEqual(u["security"], "auto")
        ss = parts["streamSettings"]
        self.assertEqual(ss["network"], "ws")
        self.assertEqual(ss["security"], "tls")
        self.assertEqual(ss["wsSettings"]["path"], "/vm")
        self.assertEqual(parts["suggested"], "мой друг")

    def test_reality_fields(self):
        parts = co._parse_vmess(_vmess_link({
            "add": "r.example.com", "port": 443,
            "id": "3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d",
            "net": "tcp", "tls": "reality", "sni": "r.example.com",
            "pbk": "PUBKEY123", "sid": "aa", "fp": "chrome"}))
        rs = parts["streamSettings"]["realitySettings"]
        self.assertEqual(rs["publicKey"], "PUBKEY123")
        self.assertEqual(rs["serverName"], "r.example.com")

    def test_broken_b64(self):
        with self.assertRaises(ValueError):
            co._parse_vmess("vmess://!!!не-base64!!!")

    def test_broken_json(self):
        with self.assertRaises(ValueError):
            co._parse_vmess("vmess://" + __import__("base64").b64encode(
                b"not json").decode())


# ══════════════════════════════════════════════════════════════════════════════
#  trojan://
# ══════════════════════════════════════════════════════════════════════════════

class TestParseTrojan(unittest.TestCase):

    def test_default_tls(self):
        parts = co._parse_trojan(
            "trojan://secretpw@t.example.com:443?sni=t.example.com#tr")
        self.assertEqual(parts["protocol"], "trojan")
        srv = parts["settings"]["servers"][0]
        self.assertEqual(srv["address"], "t.example.com")
        self.assertEqual(srv["password"], "secretpw")
        ss = parts["streamSettings"]
        self.assertEqual(ss["security"], "tls")
        self.assertEqual(ss["tlsSettings"]["serverName"], "t.example.com")

    def test_sni_falls_back_to_host(self):
        parts = co._parse_trojan("trojan://pw@5.6.7.8:443#n")
        self.assertEqual(
            parts["streamSettings"]["tlsSettings"]["serverName"], "5.6.7.8")


# ══════════════════════════════════════════════════════════════════════════════
#  ss://
# ══════════════════════════════════════════════════════════════════════════════

class TestParseSs(unittest.TestCase):

    def test_sip002_b64_userinfo(self):
        import base64
        ui = base64.b64encode(
            b"chacha20-ietf-poly1305:test-pw").decode().rstrip("=")
        parts = co._parse_ss(f"ss://{ui}@1.2.3.4:8388#MySS")
        self.assertEqual(parts["protocol"], "shadowsocks")
        srv = parts["settings"]["servers"][0]
        self.assertEqual(srv["method"], "chacha20-ietf-poly1305")
        self.assertEqual(srv["password"], "test-pw")
        self.assertEqual(srv["port"], 8388)
        self.assertEqual(parts["suggested"], "MySS")

    def test_sip002_plain_userinfo(self):
        parts = co._parse_ss(
            "ss://aes-256-gcm:plainpw@5.6.7.8:9000/?plugin=obfs-local#p")
        srv = parts["settings"]["servers"][0]
        self.assertEqual(srv["method"], "aes-256-gcm")
        self.assertEqual(srv["password"], "plainpw")
        self.assertTrue(any("плагин" in x for x in parts["warnings"]))

    def test_legacy_full_b64(self):
        import base64
        body = base64.b64encode(
            b"chacha20-ietf-poly1305:pw@9.9.9.9:1234").decode()
        parts = co._parse_ss("ss://" + body)
        srv = parts["settings"]["servers"][0]
        self.assertEqual(srv["address"], "9.9.9.9")
        self.assertEqual(srv["port"], 1234)
        self.assertEqual(srv["method"], "chacha20-ietf-poly1305")

    def test_ipv6_host(self):
        parts = co._parse_ss(
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw==@[2001:db8::5]:8388")
        srv = parts["settings"]["servers"][0]
        self.assertEqual(srv["address"], "2001:db8::5")

    def test_no_method_raises(self):
        with self.assertRaises(ValueError):
            co._parse_ss("ss://bm90aGluZ0AxLjIuMy40OjQ0Mw==")


# ══════════════════════════════════════════════════════════════════════════════
#  JSON outbound
# ══════════════════════════════════════════════════════════════════════════════

class TestParseJson(unittest.TestCase):

    def test_valid_vless(self):
        ob = {"tag": "from-v2rayn", "protocol": "vless",
              "settings": {"vnext": [{"address": "x.y", "port": 1,
                                      "users": [{"id": "u", "encryption": "none"}]}]},
              "streamSettings": {"network": "ws", "security": "tls"},
              "mux": {"enabled": False}}
        parts = co._parse_json_outbound(json.dumps(ob))
        self.assertEqual(parts["protocol"], "vless")
        self.assertEqual(parts["suggested"], "from-v2rayn")
        self.assertIn("mux", parts["extra"])
        self.assertNotIn("tag", json.dumps(parts["settings"]))

    def test_full_config_rejected(self):
        with self.assertRaises(ValueError):
            co._parse_json_outbound(json.dumps(
                {"inbounds": [], "outbounds": [{"protocol": "freedom"}]}))

    def test_no_protocol_rejected(self):
        with self.assertRaises(ValueError):
            co._parse_json_outbound('{"settings": {}}')

    def test_broken_json_rejected(self):
        with self.assertRaises(ValueError):
            co._parse_json_outbound("{не json")


# ══════════════════════════════════════════════════════════════════════════════
#  Диспетчер + валидаторы + теги
# ══════════════════════════════════════════════════════════════════════════════

class TestDispatchAndValidators(unittest.TestCase):

    def test_dispatch(self):
        parts = co.parse_share_link(VLESS_REALITY)
        self.assertEqual(parts["protocol"], "vless")

    def test_unknown_scheme(self):
        with self.assertRaises(ValueError):
            co.parse_share_link("hysteria://x@y:1")

    def test_validators(self):
        self.assertIsNone(co._co_v_host("example.com"))
        self.assertIsNone(co._co_v_host("1.2.3.4"))
        self.assertIsNone(co._co_v_host("[2001:db8::5]".strip("[").strip("]")))
        self.assertIsNotNone(co._co_v_host("bad host!"))
        self.assertIsNone(co._co_v_port("443"))
        self.assertIsNotNone(co._co_v_port("0"))
        self.assertIsNotNone(co._co_v_port("abc"))
        self.assertIsNone(co._co_v_uuid("3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d"))
        self.assertIsNotNone(co._co_v_uuid("not-uuid"))
        self.assertIsNone(co._co_v_tag("friend-1"))
        self.assertIsNotNone(co._co_v_tag("Друг"))

    def test_suggest_tag(self):
        # латиница внутри кириллического имени выживает (кейс клиента «другyyy»)
        t = co._co_suggest_tag("Друг YYY", "vless", ("1.2.3.4", 443))
        self.assertEqual(t, "yyy")
        # кириллическое имя БЕЗ латиницы → protocol-address
        self.assertEqual(co._co_suggest_tag("Друг", "vless", ("1.2.3.4", 443)),
                         "vless-1.2.3.4")
        # односимвольный остаток тоже уходит в fallback
        self.assertEqual(co._co_suggest_tag("x", "vless", ("1.2.3.4", 443)),
                         "vless-1.2.3.4")
        # валидное имя проходит как есть
        self.assertEqual(co._co_suggest_tag("friend 2", "vless", ("a", 1)),
                         "friend-2")
        # пустое → от адреса
        self.assertEqual(co._co_suggest_tag("", "socks", ("5.6.7.8", 1080)),
                         "socks-5.6.7.8")
        # совсем пусто → custom-<proto>
        self.assertEqual(co._co_suggest_tag("", "vless", ("?", "?")),
                         "custom-vless")


# ══════════════════════════════════════════════════════════════════════════════
#  State I/O
# ══════════════════════════════════════════════════════════════════════════════

class TestStateIO(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = Path(self._tmp.name) / "co.json"
        patcher = patch.object(co, "CO_STATE_FILE", self._state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def test_load_empty(self):
        st = co._co_load()
        self.assertEqual(st, {"version": 1, "outbounds": []})

    def test_roundtrip_and_tags(self):
        st = {"version": 1, "outbounds": [_entry("a"), _entry("b", enabled=False)]}
        co._co_save(st)
        st2 = co._co_load()
        self.assertEqual([e["name"] for e in st2["outbounds"]], ["a", "b"])
        self.assertEqual(co.co_state_tags(), {"a", "b"})


# ══════════════════════════════════════════════════════════════════════════════
#  apply / restore (tmp-конфиги, мок xray run -test)
# ══════════════════════════════════════════════════════════════════════════════

class _CfgEnv(unittest.TestCase):
    """tmp /etc/xray/config.json + alt + state; _run замокан (xray -test)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.cfg_dir = root / "etc"
        self.cfg_dir.mkdir()
        self.cfg_main = self.cfg_dir / "config.json"
        self.cfg_alt = root / "alt" / "config.json"
        self.cfg_alt.parent.mkdir()
        self.state_file = root / "co.json"

        self.cfg_main.write_text(json.dumps(_mk_cfg()))
        self.cfg_alt.write_text(json.dumps(_mk_cfg()))

        for p, attr in ((self.cfg_dir, "_CONFIG_DIR"),
                        (self.cfg_alt, "_ALT_CONFIG"),
                        (self.state_file, "CO_STATE_FILE")):
            patcher = patch.object(co, attr, p)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.run_mock = MagicMock(return_value=_ok_run(0))
        run_patcher = patch.object(co, "_run", self.run_mock)
        run_patcher.start()
        self.addCleanup(run_patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, path):
        return json.loads(Path(path).read_text())

    def _save_state(self, entries):
        """Реальный флоу меню: load→modify→save (сохраняет known_tags)."""
        st = co._co_load()
        st["outbounds"] = entries
        co._co_save(st)


class TestApplyToXray(_CfgEnv):

    def test_append_enabled(self):
        self._save_state([_entry("friend-1")])
        self.assertTrue(co._co_apply_to_xray(validate=True))
        cfg = self._load(self.cfg_main)
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK", "friend-1"])
        ob = cfg["outbounds"][2]
        self.assertEqual(ob["protocol"], "vless")
        # оба конфига пропатчены
        self.assertEqual(
            [o["tag"] for o in self._load(self.cfg_alt)["outbounds"]],
            tags)
        # валидация была запущена на оба конфига
        self.assertEqual(self.run_mock.call_count, 2)

    def test_idempotent(self):
        self._save_state([_entry("friend-1")])
        co._co_apply_to_xray()
        co._co_apply_to_xray()
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK", "friend-1"])

    def test_disabled_removed(self):
        self._save_state([_entry("friend-1", enabled=False)])
        co._co_apply_to_xray()
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK"])

    def test_delete_last_entry_no_orphan(self):
        # E2E-кейс: удаление ПОСЛЕДНЕГО entry из state (как _co_menu_delete)
        # без known_tags теряло знание о теге → осиротевший outbound навсегда
        self._save_state([_entry("friend-1")])
        co._co_apply_to_xray()
        self.assertIn("friend-1",
                      [o["tag"] for o in self._load(self.cfg_main)["outbounds"]])
        self._save_state([])
        co._co_apply_to_xray()
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK"])
        # known_tags зафиксирован в state
        st = co._co_load()
        self.assertIn("friend-1", st.get("known_tags", []))

    def test_validate_fail_keeps_known_unsaved(self):
        # при отказе Xray known_tags не фиксируется (конфиг откачен)
        self._save_state([_entry("friend-1")])
        self.run_mock.return_value = _ok_run(1, "boom")
        self.assertFalse(co._co_apply_to_xray(validate=True))
        self.assertEqual(co._co_load().get("known_tags", []), [])

    def test_replaced_not_duplicated(self):
        self._save_state([_entry("friend-1")])
        co._co_apply_to_xray()
        # «regenerate» стёр + вернул дефолтные
        self.cfg_main.write_text(json.dumps(_mk_cfg()))
        # замена определения с тем же тегом
        self._save_state([_entry("friend-1", proto="vmess", addr="9.9.9.9")])
        co._co_apply_to_xray()
        cfg = self._load(self.cfg_main)
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK", "friend-1"])
        self.assertEqual(cfg["outbounds"][2]["protocol"], "vmess")

    def test_default_outbound_untouched(self):
        self._save_state([_entry("friend-1")])
        co._co_apply_to_xray()
        cfg = self._load(self.cfg_main)
        self.assertEqual(cfg["outbounds"][0]["tag"], "direct")
        self.assertEqual(cfg["routing"]["rules"][0]["outboundTag"], "direct")

    def test_validate_fail_rolls_back(self):
        before_main = self.cfg_main.read_text()
        before_alt = self.cfg_alt.read_text()
        self._save_state([_entry("friend-1")])
        self.run_mock.return_value = _ok_run(1, "boom")
        self.assertFalse(co._co_apply_to_xray(validate=True))
        self.assertEqual(self.cfg_main.read_text(), before_main)
        self.assertEqual(self.cfg_alt.read_text(), before_alt)

    def test_no_configs(self):
        self.cfg_main.unlink()
        self.cfg_alt.unlink()
        with patch.object(co, "_warn"):
            self.assertFalse(co._co_apply_to_xray())


class TestRestore(_CfgEnv):

    def test_noop_when_no_state(self):
        self.assertFalse(co.restore_custom_outbounds_if_needed(silent=True))

    def test_noop_when_present(self):
        self._save_state([_entry("friend-1")])
        co._co_apply_to_xray()
        self.assertFalse(co.restore_custom_outbounds_if_needed(silent=True))

    def test_reapplies_after_regenerate(self):
        self._save_state([_entry("friend-1"), _entry("friend-2", enabled=False)])
        co._co_apply_to_xray()
        # simulate regenerate: конфиг пересобран без кастомных
        self.cfg_main.write_text(json.dumps(_mk_cfg()))
        self.cfg_alt.write_text(json.dumps(_mk_cfg()))
        self.assertTrue(co.restore_custom_outbounds_if_needed(silent=True))
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK", "friend-1"])
        alt_tags = [o["tag"] for o in self._load(self.cfg_alt)["outbounds"]]
        self.assertEqual(alt_tags, tags)

    def test_disabled_not_restored(self):
        self._save_state([_entry("friend-1", enabled=False)])
        self.assertFalse(co.restore_custom_outbounds_if_needed(silent=True))
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK"])


class TestRefsAndDescribe(unittest.TestCase):

    def test_refs_in_routing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp)
            main = cfg_dir / "config.json"
            main.write_text(json.dumps(_mk_cfg(rules=[
                {"type": "field", "outboundTag": "friend-1",
                 "ip": ["1.0.0.0/8"], "comment": "custom:ru-via-friend"},
                {"type": "field", "outboundTag": "direct",
                 "network": "tcp,udp"},
            ])))
            with patch.object(co, "_CONFIG_DIR", cfg_dir), \
                 patch.object(co, "_ALT_CONFIG", Path(tmp) / "nope.json"):
                refs = co._co_refs_in_routing("friend-1")
                self.assertEqual(refs, ["custom:ru-via-friend"])
                self.assertEqual(co._co_refs_in_routing("absent"), [])

    def test_describe_and_target(self):
        e = _entry("x")
        self.assertIn("vless", co._co_describe(e))
        self.assertIn("tcp/reality", co._co_describe(e))
        self.assertEqual(co._co_target(e["outbound"]), ("1.2.3.4", 443))

    def test_mask(self):
        self.assertEqual(co._co_mask("abcd", 4), "•" * 4)
        self.assertTrue(co._co_mask("abcdefgh1234", 4).startswith("abcd"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
