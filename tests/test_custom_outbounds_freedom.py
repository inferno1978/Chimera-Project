#!/usr/bin/env python3
"""
tests/test_custom_outbounds_freedom.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты freedom-ветки кастомных outbound'ов (chimera/modules/custom_outbounds.py).

Кейс (15.11, продолжение саги «B4-панель не открывается через туннель»):
v6-транзит хостера exit-ноды → панель починен наполовину — SYN доходит,
SYN-ACK тонет (чёрная дыра обратного направления между v6-блоками хостера).
freedom UseIPv6v4 на exit не делает быстрый fallback: dial висит в мёртвом
v6 минутами (живой стенд: socks через временный xray с теми же настройками —
40 c без попытки v4). Обход внутри флота — пер-доменное правило «панели →
freedom UseIPv4»: нужен кастомный freedom-outbound (тег direct-v4) +
routing-правило на домены панелей. До правки freedom можно было добавить
только готовым JSON (мастер — только vless/vmess/trojan/ss/socks/http).

Покрывает:
  1. Константы: freedom в CO_PROTOCOLS, наборы стратегий/подписей
  2. _co_v_ip_opt — валидатор sendThrough (пусто/v4/v6/скобки/мусор)
  3. _co_freedom_default_tag — UseIPv4 → direct-v4 (канон кейса), иначе
     freedom-<стратегия>
  4. _co_wizard_freedom — мини-форма мастера: дуал-запись domainStrategy
     (settings + sockopt — конвенция domain_strategy), sendThrough опц.,
     WARN при UseIPv6*-стратегии, отмена на select/форме, префилл, делегация
     из _co_wizard
  5. _co_describe — «freedom  UseIPv4 [src …]» вместо «?:? tcp/none»
  6. _co_extract_spec — префилл замены (dsStrategy/sendThrough, без
     сетевых полей)
  7. _co_preview — Egress/sendThrough вместо «Адрес», без «Транспорта»
  8. _co_tcp_check — freedom: цель неприменима, коннект не выполняется
     (контроль: vless-цель проверяется)
  9. JSON-путь: однострочный freedom-outbound по-прежнему принимается
     (suggested из tag)
  10. apply: freedom-entry доезжает до обоих конфигов как есть (дуал-запись
      сохранена, tag инжектится), идемпотентность, выключение убирает
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


def _mk_cfg() -> dict:
    return {
        "inbounds": [{"protocol": "vless", "tag": "in", "port": 443}],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {"rules": [
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]},
    }


def _freedom_entry(name="direct-v4", enabled=True, ds="UseIPv4",
                   send_through=None):
    ob = co.make_freedom_outbound(name, ds, send_through=send_through)
    ob.pop("tag", None)  # apply инжектит tag из name (канон _entry)
    return {"name": name, "enabled": enabled, "source": "wizard",
            "outbound": ob,
            "created_at": "2026-11-15 00:00:00",
            "updated_at": "2026-11-15 00:00:00"}


# ══════════════════════════════════════════════════════════════════════════════
#  1. Константы
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomConstants(unittest.TestCase):

    def test_freedom_in_protocols(self):
        self.assertIn("freedom", co.CO_PROTOCOLS)

    def test_ds_sets_consistent(self):
        self.assertEqual(len(co.CO_DS_STRATEGIES), len(co.CO_DS_LABELS))
        self.assertEqual(len(set(co.CO_DS_STRATEGIES)),
                         len(co.CO_DS_STRATEGIES))
        # дефолт пикера — UseIPv4 (самый частый кейс: v4-пин доменов)
        self.assertEqual(co.CO_DS_STRATEGIES[0], "UseIPv4")
        for s in ("UseIPv4", "UseIPv6v4", "UseIPv4v6", "UseIPv6",
                  "UseIP", "AsIs"):
            self.assertIn(s, co.CO_DS_STRATEGIES)


# ══════════════════════════════════════════════════════════════════════════════
#  2. Валидатор sendThrough
# ══════════════════════════════════════════════════════════════════════════════

class TestIpOptValidator(unittest.TestCase):

    def test_cases(self):
        self.assertIsNone(co._co_v_ip_opt(""))
        self.assertIsNone(co._co_v_ip_opt("   "))
        self.assertIsNone(co._co_v_ip_opt("10.0.0.2"))
        self.assertIsNone(co._co_v_ip_opt("172.16.0.1"))
        self.assertIsNone(co._co_v_ip_opt("2001:db8::1"))
        self.assertIsNone(co._co_v_ip_opt("[2001:db8::1]"))
        self.assertIsNotNone(co._co_v_ip_opt("example.com"))
        self.assertIsNotNone(co._co_v_ip_opt("10.0.0.2:443"))
        self.assertIsNotNone(co._co_v_ip_opt("10.0.0"))


# ══════════════════════════════════════════════════════════════════════════════
#  3. Дефолт-тег
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomDefaultTag(unittest.TestCase):

    def test_cases(self):
        self.assertEqual(co._co_freedom_default_tag("UseIPv4"), "direct-v4")
        self.assertEqual(co._co_freedom_default_tag("UseIPv6v4"),
                         "freedom-useipv6v4")
        self.assertEqual(co._co_freedom_default_tag("AsIs"), "freedom-asis")
        self.assertEqual(co._co_freedom_default_tag(""), "freedom-asis")
        # результат всегда проходит валидатор тега
        for ds in co.CO_DS_STRATEGIES:
            self.assertIsNone(co._co_v_tag(co._co_freedom_default_tag(ds)))


# ══════════════════════════════════════════════════════════════════════════════
#  4. Мастер freedom
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomWizard(unittest.TestCase):

    def _run_wizard(self, select_idx=0, form=None, spec=None):
        sel = MagicMock(return_value=select_idx)
        frm = MagicMock(return_value={"sendThrough": form or ""})
        with patch.object(co, "tui_select", sel), \
                patch.object(co, "tui_form", frm):
            res = co._co_wizard_freedom(spec or {})
        return res, sel, frm

    def test_useipv4_minimal(self):
        res, _, _ = self._run_wizard(select_idx=0, form="")
        self.assertIsNotNone(res)
        settings, stream, warnings = res
        self.assertEqual(settings, {"domainStrategy": "UseIPv4"})
        # дуал-запись: sockopt-форма обязательна (конвенция domain_strategy)
        self.assertEqual(stream["sockopt"]["domainStrategy"], "UseIPv4")
        self.assertEqual(warnings, [])

    def test_sendthrough_included(self):
        res, _, _ = self._run_wizard(select_idx=0, form="172.16.0.1")
        settings, _, _ = res
        self.assertEqual(settings["domainStrategy"], "UseIPv4")
        self.assertEqual(settings["sendThrough"], "172.16.0.1")

    def test_v6_strategy_warns(self):
        res, _, _ = self._run_wizard(select_idx=1, form="")  # UseIPv6v4
        _, _, warnings = res
        self.assertEqual(len(warnings), 1)
        self.assertIn("IPv6", warnings[0])

    def test_v4_first_strategy_no_warn(self):
        res, _, _ = self._run_wizard(select_idx=2, form="")  # UseIPv4v6
        settings, _, warnings = res
        self.assertEqual(settings["domainStrategy"], "UseIPv4v6")
        self.assertEqual(warnings, [])

    def test_prefill_default_index(self):
        _, sel, _ = self._run_wizard(
            select_idx=1, form="",
            spec={"dsStrategy": "UseIPv6v4", "sendThrough": "10.0.0.9"})
        self.assertEqual(sel.call_args.kwargs.get("default"), 1)

    def test_prefill_unknown_strategy_defaults_v4(self):
        _, sel, _ = self._run_wizard(select_idx=0, form="",
                                     spec={"dsStrategy": "мусор"})
        self.assertEqual(sel.call_args.kwargs.get("default"), 0)

    def test_cancel_on_select(self):
        sel = MagicMock(return_value=None)
        with patch.object(co, "tui_select", sel), \
                patch.object(co, "tui_form", MagicMock()):
            self.assertIsNone(co._co_wizard_freedom({}))

    def test_cancel_on_form(self):
        with patch.object(co, "tui_select", MagicMock(return_value=0)), \
                patch.object(co, "tui_form", MagicMock(return_value=None)):
            self.assertIsNone(co._co_wizard_freedom({}))

    def test_wizard_delegates_to_freedom_branch(self):
        with patch.object(co, "_co_wizard_freedom",
                          MagicMock(return_value=({"a": 1}, None, []))) as wf:
            res = co._co_wizard("freedom", {"dsStrategy": "UseIPv4"})
        wf.assert_called_once_with({"dsStrategy": "UseIPv4"})
        self.assertEqual(res, ({"a": 1}, None, []))

    def test_sendthrough_v6_literal(self):
        res, _, _ = self._run_wizard(select_idx=0, form="2001:db8::2")
        settings, _, _ = res
        self.assertEqual(settings["sendThrough"], "2001:db8::2")


# ══════════════════════════════════════════════════════════════════════════════
#  5-6. Сводка списка + префилл замены
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomDescribeAndSpec(unittest.TestCase):

    def test_describe_plain(self):
        e = _freedom_entry()
        self.assertEqual(co._co_describe(e), "freedom  UseIPv4")
        self.assertNotIn("?:?", co._co_describe(e))

    def test_describe_with_sendthrough(self):
        e = _freedom_entry(ds="UseIPv6v4", send_through="172.16.0.1")
        self.assertEqual(co._co_describe(e),
                         "freedom  UseIPv6v4  src 172.16.0.1")

    def test_extract_spec(self):
        ob = co.make_freedom_outbound("x", "UseIPv6v4",
                                      send_through="10.0.0.7")
        spec = co._co_extract_spec(ob)
        self.assertEqual(spec.get("dsStrategy"), "UseIPv6v4")
        self.assertEqual(spec.get("sendThrough"), "10.0.0.7")
        # у freedom нет транспорта — сетевые поля не подтягиваются
        self.assertNotIn("network", spec)
        self.assertNotIn("security", spec)

    def test_extract_spec_no_sendthrough(self):
        ob = co.make_freedom_outbound("x", "UseIP")
        spec = co._co_extract_spec(ob)
        self.assertEqual(spec.get("dsStrategy"), "UseIP")
        self.assertNotIn("sendThrough", spec)


# ══════════════════════════════════════════════════════════════════════════════
#  7. Превью
# ══════════════════════════════════════════════════════════════════════════════

_BOX_FUNCS = ("_box_top", "_box_bottom", "_box_row", "_box_sep",
              "_box_desc", "_box_warn", "_box_ok", "_box_kv")


class TestFreedomPreview(unittest.TestCase):

    def _preview(self, parts):
        kv = MagicMock()
        with patch.object(co, "_box_kv", kv), \
                patch.object(co, "tui_confirm",
                             MagicMock(return_value=True)), \
                patch.multiple(co, **{fn: MagicMock()
                                       for fn in _BOX_FUNCS
                                       if fn != "_box_kv"}):
            ok = co._co_preview("direct-v4", parts, [], None)
        return ok, kv

    def test_freedom_preview(self):
        entry = _freedom_entry()
        parts = {"protocol": "freedom",
                 "settings": entry["outbound"]["settings"],
                 "streamSettings": entry["outbound"]["streamSettings"]}
        ok, kv = self._preview(parts)
        self.assertTrue(ok)
        calls = [str(c.args) for c in kv.call_args_list]
        self.assertTrue(any("Egress" in c and "UseIPv4" in c for c in calls),
                        f"нет Egress в {calls}")
        self.assertFalse(any("Адрес" in c for c in calls),
                          f"Адрес не должен печататься: {calls}")
        self.assertFalse(any("Транспорт" in c for c in calls),
                          f"Транспорт не должен печататься: {calls}")

    def test_freedom_preview_sendthrough(self):
        entry = _freedom_entry(send_through="172.16.0.1")
        parts = {"protocol": "freedom",
                 "settings": entry["outbound"]["settings"],
                 "streamSettings": entry["outbound"]["streamSettings"]}
        _, kv = self._preview(parts)
        calls = [str(c.args) for c in kv.call_args_list]
        self.assertTrue(any("sendThrough" in c and "172.16.0.1" in c
                            for c in calls), f"нет sendThrough в {calls}")

    def test_vless_preview_keeps_address(self):
        # регресс: у «обычных» протоколов Адрес/Транспорт остаются
        parts = {"protocol": "vless",
                 "settings": {"vnext": [{"address": "1.2.3.4", "port": 443,
                                         "users": [{"id": "x"}]}]},
                 "streamSettings": {"network": "ws", "security": "tls"}}
        _, kv = self._preview(parts)
        calls = [str(c.args) for c in kv.call_args_list]
        self.assertTrue(any("Адрес" in c and "1.2.3.4" in c for c in calls))
        self.assertTrue(any("Транспорт" in c for c in calls))


# ══════════════════════════════════════════════════════════════════════════════
#  8. TCP-проверка
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomTcpCheck(unittest.TestCase):

    def test_freedom_skips_connect(self):
        cc = MagicMock()
        with patch.object(co.socket, "create_connection", cc), \
                patch.multiple(co, **{fn: MagicMock()
                                      for fn in _BOX_FUNCS + ("_box_item",
                                                              "_box_back")}):
            co._co_tcp_check(_freedom_entry())
        cc.assert_not_called()

    def test_vless_control_connects(self):
        cc = MagicMock()  # MagicMock поддерживает контекстный протокол
        with patch.object(co.socket, "create_connection", cc), \
                patch.multiple(co, **{fn: MagicMock()
                                      for fn in _BOX_FUNCS + ("_box_item",
                                                              "_box_back")}):
            entry = {"name": "friend-1", "outbound": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "1.2.3.4", "port": 443,
                                        "users": [{"id": "x"}]}]},
                "streamSettings": {"network": "tcp", "security": "none"}}}
            co._co_tcp_check(entry)
        cc.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
#  9. JSON-путь
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomJsonPath(unittest.TestCase):

    def test_freedom_one_liner(self):
        parts = co._parse_json_outbound(
            '{"protocol":"freedom","tag":"direct-v4",'
            '"settings":{"domainStrategy":"UseIPv4"}}')
        self.assertEqual(parts["protocol"], "freedom")
        self.assertEqual(parts["settings"], {"domainStrategy": "UseIPv4"})
        self.assertEqual(parts["suggested"], "direct-v4")

    def test_freedom_no_settings_ok(self):
        # freedom без settings валиден (AsIs-поведение) — WARN не должен
        # навешиваться (он только для vless/vmess/trojan/ss/socks/http)
        parts = co._parse_json_outbound('{"protocol":"freedom"}')
        self.assertEqual(parts["protocol"], "freedom")
        self.assertEqual(parts["warnings"], [])


# ══════════════════════════════════════════════════════════════════════════════
#  10. apply (tmp-конфиги, мок xray run -test)
# ══════════════════════════════════════════════════════════════════════════════

class TestFreedomApply(unittest.TestCase):

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
        st = co._co_load()
        st["outbounds"] = entries
        co._co_save(st)

    def test_freedom_appended_dual_write_intact(self):
        self._save_state([_freedom_entry()])
        self.assertTrue(co._co_apply_to_xray(validate=True))
        cfg = self._load(self.cfg_main)
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK", "direct-v4"])
        ob = cfg["outbounds"][2]
        self.assertEqual(ob["protocol"], "freedom")
        # дуал-запись пережила сериализацию в конфиг
        self.assertEqual(ob["settings"]["domainStrategy"], "UseIPv4")
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4")
        # оба конфига пропатчены
        self.assertEqual(
            [o["tag"] for o in self._load(self.cfg_alt)["outbounds"]], tags)
        self.assertEqual(self.run_mock.call_count, 2)

    def test_freedom_sendthrough_survives(self):
        self._save_state([_freedom_entry(send_through="172.16.0.1")])
        self.assertTrue(co._co_apply_to_xray())
        ob = self._load(self.cfg_main)["outbounds"][2]
        self.assertEqual(ob["settings"]["sendThrough"], "172.16.0.1")

    def test_idempotent(self):
        self._save_state([_freedom_entry()])
        co._co_apply_to_xray()
        co._co_apply_to_xray()
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK", "direct-v4"])

    def test_disabled_removed(self):
        self._save_state([_freedom_entry(enabled=False)])
        co._co_apply_to_xray()
        tags = [o["tag"] for o in self._load(self.cfg_main)["outbounds"]]
        self.assertEqual(tags, ["direct", "BLOCK"])

    def test_default_outbound_untouched(self):
        self._save_state([_freedom_entry()])
        co._co_apply_to_xray()
        cfg = self._load(self.cfg_main)
        # дефолтный outbound (первый, direct) не получил настроек кастомного
        self.assertEqual(cfg["outbounds"][0]["tag"], "direct")
        self.assertEqual(cfg["outbounds"][0].get("settings", {}), {})
        self.assertNotEqual(
            cfg["outbounds"][0].get("settings", {}).get("domainStrategy"),
            "UseIPv4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
