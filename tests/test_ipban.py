#!/usr/bin/env python3
"""
tests/test_ipban.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ipban.py.

Покрывает:
  1. _parse_ip — парсинг IPv4/IPv6
  2. _parse_cidr — парсинг CIDR
  3. _parse_range — парсинг диапазона
  4. _asn_normalize — нормализация ASN
  5. _detect_input_kind — классификатор ввода
  6. _state_load / _state_save — JSON I/O
  7. _state_add_entry / _state_remove_entry — CRUD
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
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


class TestParseIp(unittest.TestCase):
    """_parse_ip — парсинг IP."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4(self):
        from chimera.modules.ipban import _parse_ip
        self.assertEqual(_parse_ip("1.2.3.4"), ["1.2.3.4/32"])

    def test_ipv6(self):
        from chimera.modules.ipban import _parse_ip
        self.assertEqual(_parse_ip("::1"), ["::1/128"])
        self.assertEqual(_parse_ip("2001:db8::1"), ["2001:db8::1/128"])

    def test_invalid_raises(self):
        from chimera.modules.ipban import _parse_ip
        with self.assertRaises(ValueError):
            _parse_ip("invalid")


class TestParseCidr(unittest.TestCase):
    """_parse_cidr — парсинг CIDR."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_cidr(self):
        from chimera.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("10.0.0.0/24"), ["10.0.0.0/24"])

    def test_normalizes_non_strict(self):
        """10.0.0.5/24 нормализуется в 10.0.0.0/24."""
        from chimera.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("10.0.0.5/24"), ["10.0.0.0/24"])

    def test_ipv6_cidr(self):
        from chimera.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("2001:db8::/32"), ["2001:db8::/32"])


class TestParseRange(unittest.TestCase):
    """_parse_range — парсинг диапазона."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_range(self):
        from chimera.modules.ipban import _parse_range
        result = _parse_range("1.2.3.0-1.2.3.255")
        self.assertGreater(len(result), 0)
        # summarize_address_range даёт ["1.2.3.0/24"]
        self.assertIn("1.2.3.0/24", result)

    def test_reversed_range_swapped(self):
        """Если start > end — меняются местами."""
        from chimera.modules.ipban import _parse_range
        result = _parse_range("1.2.3.255-1.2.3.0")
        self.assertIn("1.2.3.0/24", result)

    def test_no_hyphen_raises(self):
        from chimera.modules.ipban import _parse_range
        with self.assertRaises(ValueError):
            _parse_range("1.2.3.4")


class TestAsnNormalize(unittest.TestCase):
    """_asn_normalize — нормализация ASN."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_adds_as_prefix(self):
        from chimera.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("12345"), "AS12345")

    def test_uppercase(self):
        from chimera.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("as12345"), "AS12345")

    def test_already_prefixed(self):
        from chimera.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("AS12345"), "AS12345")
        self.assertEqual(_asn_normalize("as12345"), "AS12345")


class TestDetectInputKind(unittest.TestCase):
    """_detect_input_kind — классификатор."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_asn_with_prefix(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("AS12345"), "asn")

    def test_asn_numeric(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("12345"), "asn")

    def test_cidr(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("10.0.0.0/24"), "cidr")

    def test_range(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("1.2.3.0-1.2.3.255"), "range")

    def test_ip(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("1.2.3.4"), "ip")

    def test_ipv6_is_ip(self):
        """IPv6 без / → 'ip' (нет дефиса, нет /)."""
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("2001:db8::1"), "ip")


class TestStateLoadSave(unittest.TestCase):
    """_state_load / _state_save."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "ipban.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.ipban._STATE_FILE", self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.ipban import _state_load
        with self._patch():
            result = _state_load()
        self.assertEqual(result, {"entries": []})

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.ipban import _state_load
        self._state.write_text("{invalid")
        with self._patch():
            result = _state_load()
        self.assertEqual(result, {"entries": []})

    def test_save_then_load(self):
        from chimera.modules.ipban import _state_load, _state_save
        with self._patch():
            _state_save({"entries": [{"display": "x"}]})
            loaded = _state_load()
        self.assertEqual(len(loaded["entries"]), 1)


class TestStateAddRemoveEntry(unittest.TestCase):
    """_state_add_entry / _state_remove_entry."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "ipban.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.ipban._STATE_FILE", self._state)

    def test_add_new_entry(self):
        from chimera.modules.ipban import (
            _state_add_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("1.2.3.4/32", ["1.2.3.4/32"], "ip")
            state = _state_load()
        self.assertEqual(len(state["entries"]), 1)
        self.assertEqual(state["entries"][0]["display"], "1.2.3.4/32")
        self.assertEqual(state["entries"][0]["kind"], "ip")

    def test_add_replaces_duplicate_by_display(self):
        """Добавление с тем же display — заменяет старую."""
        from chimera.modules.ipban import (
            _state_add_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("test", ["1.0.0.0/8"], "cidr", "old")
            _state_add_entry("test", ["2.0.0.0/8"], "cidr", "new")
            state = _state_load()
        self.assertEqual(len(state["entries"]), 1)
        self.assertEqual(state["entries"][0]["comment"], "new")

    def test_remove_existing_entry(self):
        from chimera.modules.ipban import (
            _state_add_entry, _state_remove_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("test", ["1.0.0.0/8"], "cidr")
            self.assertTrue(_state_remove_entry("test"))
            state = _state_load()
        self.assertEqual(len(state["entries"]), 0)

    def test_remove_nonexistent_returns_false(self):
        from chimera.modules.ipban import _state_remove_entry
        with self._patch():
            self.assertFalse(_state_remove_entry("nonexistent"))


# ============================================================================
#  Порядок правил + персистентность (кейс vds14808 / AS25369, 2026-09-21)
# ============================================================================
from unittest.mock import MagicMock


class _FakeRunner:
    """Рекордер subprocess.run с управляемыми кодами возврата."""

    def __init__(self):
        self.calls: list = []

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        rc = 1
        if cmd[:2] == ["ipset", "create"]:
            rc = 0
        elif cmd[0] == "systemctl":
            rc = 0
        elif "-C" in cmd:
            rc = 1   # правило не найдено → вставка выполнится
        elif "-D" in cmd:
            rc = 1   # нечего удалять → цикл миграции прерывается сразу
        elif "-I" in cmd:
            rc = 0
        elif "which" == cmd[0]:
            rc = 0
        r = MagicMock()
        r.returncode = rc
        r.stdout = ""
        r.stderr = ""
        return r


class TestRulesOrderingAndPersistence(unittest.TestCase):
    """Правила банa обязаны стоять ПЕРВОЙ строкой INPUT — до ufw-цепочек.

    Регрессия кейса AS25369 (2026-09-21): при включённом UFW (дефолт
    Chimera) пакеты на открытые порты принимаются внутри
    ufw-before-input/ufw-user-input (first-match-wins) и НИКОГДА не
    доходят до правила, добавленного -A INPUT (в конец) → бан ASN был
    декоративным. Дополнительно: ipset_persist восстанавливает только
    сеты, правила iptables после reboot терялись.
    """

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._runner = _FakeRunner()
        _p1 = patch("chimera.modules.ipban.subprocess.run", self._runner)
        _p1.start()
        self.addCleanup(_p1.stop)
        _p2 = patch("chimera.modules.ipban._BOOT_UNIT",
                    self._tmp / "xray-ipban-restore.service")
        _p2.start()
        self.addCleanup(_p2.stop)
        _p3 = patch("chimera.modules.ipban._BOOT_SCRIPT",
                    self._tmp / "xray-ipban-boot.sh")
        _p3.start()
        self.addCleanup(_p3.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_rule_spec_includes_comment(self):
        """-C/-D/-I используют единый spec с comment-матчером.

        Старый код проверял -C БЕЗ comment, а правило создавал С
        comment → проверка никогда не находила правило → дубликаты.
        """
        from chimera.modules.ipban import _iptables_rule_spec, _COMMENT
        spec = _iptables_rule_spec("xray_manual_ban")
        self.assertIn("-m", spec)
        self.assertIn("comment", spec)
        self.assertIn(_COMMENT, spec)

    def test_ensure_uses_insert_at_top_not_append(self):
        """Правило вставляется -I INPUT 1, НЕ -A INPUT (в конец)."""
        from chimera.modules.ipban import _ensure_iptables_rules
        _ensure_iptables_rules()
        inserted = [c for c in self._runner.calls if c[:4] == ["iptables", "-I", "INPUT", "1"]]
        self.assertTrue(inserted, "iptables -I INPUT 1 не вызван")
        for c in inserted:
            self.assertIn("--match-set", c)
            self.assertIn("xray_manual_ban", c)
        inserted6 = [c for c in self._runner.calls if c[:4] == ["ip6tables", "-I", "INPUT", "1"]]
        self.assertTrue(inserted6, "ip6tables -I INPUT 1 не вызван")
        appended = [c for c in self._runner.calls if c[:3] in (
            ["iptables", "-A", "INPUT"], ["ip6tables", "-A", "INPUT"])]
        self.assertFalse(appended, f"-A INPUT запрещён (недостижимо за ufw): {appended}")

    def test_ensure_migrates_old_appended_rules(self):
        """Старые правила (любой spec-вариант) удаляются перед вставкой."""
        from chimera.modules.ipban import _ensure_iptables_rules
        _ensure_iptables_rules()
        deletes = [c for c in self._runner.calls if c[:3] == ["iptables", "-D", "INPUT"]]
        self.assertTrue(deletes, "миграция: старые правила не удаляются")
        # удаляются ОБА варианта spec — с comment и без
        with_comment = [c for c in deletes if "comment" in c]
        without_comment = [c for c in deletes if "comment" not in c]
        self.assertTrue(with_comment, "миграция не удаляет вариант с comment")
        self.assertTrue(without_comment, "миграция не удаляет вариант без comment")

    def test_boot_unit_created_and_persists_rules(self):
        """После reboot юнит запускает boot-скрипт: сеты + элементы +
        правила INPUT 1 + самолечение персистенса (3-я инкарнация юнита —
        после кейса тихого испарения бана ГРЧЦ, окт.2026)."""
        from chimera.modules.ipban import _ensure_boot_unit, _BOOT_UNIT, _BOOT_SCRIPT
        _ensure_boot_unit()
        self.assertTrue(_BOOT_UNIT.exists(), "юнит не записан")
        self.assertTrue(_BOOT_SCRIPT.exists(), "boot-скрипт не записан")
        unit = _BOOT_UNIT.read_text(encoding="utf-8")
        script = _BOOT_SCRIPT.read_text(encoding="utf-8")
        # юнит исполняет самодостаточный скрипт
        self.assertIn(f"ExecStart={_BOOT_SCRIPT}", unit)
        self.assertIn("After=telemt-iptables.service xray-ipset-restore.service", unit)
        self.assertIn("Before=xray.service", unit)
        # скрипт: сеты + элементы из state-снапшота + правила + самолечение
        self.assertIn("ipset create xray_manual_ban", script)
        self.assertIn("-exist", script)
        self.assertIn("/var/lib/xray-installer/ipban.cidrs", script)
        self.assertIn("-I INPUT 1", script,
                      "скрипт восстанавливает правило НЕ первой строкой")
        self.assertIn("xray_manual_ban6", script)
        self.assertIn("grep -vE", script, "нет самолечения /etc/ipset.conf")
        # enable вызван
        enabled = [c for c in self._runner.calls
                   if c[:2] == ["systemctl", "enable"]]
        self.assertTrue(enabled, "systemctl enable юнита не вызван")

    def test_ipban_add_bootstraps_rules_and_unit(self):
        """ipban_add ставит правила + юнит (мокается только резолв CIDR)."""
        import chimera.modules.ipban as ipban
        with patch.object(ipban, "_resolve_to_cidrs",
                          return_value=("1.2.3.4", "ip", ["1.2.3.4/32"])), \
             patch.object(ipban, "_ensure_sets", return_value=True), \
             patch.object(ipban, "_state_add_entry"), \
             patch.object(ipban, "_ipban_persist_save"):
            ipban.ipban_add("1.2.3.4")
        top_insert = [c for c in self._runner.calls if c[:4] == ["iptables", "-I", "INPUT", "1"]]
        self.assertTrue(top_insert, "ipban_add не вставил правило в вершину INPUT")
        unit_calls = [c for c in self._runner.calls if c[:2] == ["systemctl", "enable"]]
        self.assertTrue(unit_calls, "ipban_add не установил boot-юнит")


# ============================================================================
#  Тихое испарение бана (кейс ГРЧЦ AS61280, Москва, окт.2026):
#  /etc/ipset.conf затёрт сторонним сейвером + ребут → live пуст
#  при живом state. Фикс: state — источник истины, персист ← state ∪ live,
#  boot-скрипт восстанавливает элементы из снапшота ipban.cidrs.
# ============================================================================


class _IpsetSim:
    """Симулятор ipset/iptables-подсистемы (сеты + элементы в памяти)."""

    def __init__(self, sets=None):
        self.sets: dict = dict(sets or {})          # name -> set(cidr)
        self.calls: list = []

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        r = MagicMock()
        r.stderr = ""
        r.stdout = ""
        r.returncode = 0
        if cmd[:2] == ["ipset", "create"]:
            self.sets.setdefault(cmd[2], set())
        elif cmd[:2] == ["ipset", "add"]:
            name, cidr = cmd[2], cmd[3]
            if name not in self.sets:
                r.returncode = 1
            else:
                self.sets[name].add(cidr)
        elif cmd[:2] == ["ipset", "del"]:
            self.sets.get(cmd[2], set()).discard(cmd[3])
        elif cmd[:2] == ["ipset", "list"]:
            if "-n" in cmd:                          # ["ipset","list","-n",name]
                name = cmd[3] if len(cmd) > 3 else cmd[2]
                r.returncode = 0 if name in self.sets else 1
            else:                                    # ["ipset","list",name]
                name = cmd[2]
                if name not in self.sets:
                    r.returncode = 1
                else:
                    members = "\n".join(sorted(self.sets[name]))
                    r.stdout = f"Name: {name}\nType: hash:net\nMembers:\n{members}\n"
        elif cmd[0] == "which":
            r.returncode = 0
        elif cmd[0] in ("iptables", "ip6tables"):
            r.returncode = 1 if ("-C" in cmd or "-D" in cmd) else 0
        return r


_GRCHC_CIDRS = [
    "45.132.21.0/24", "45.157.4.0/24", "62.76.12.0/24", "85.142.6.0/24",
    "87.245.160.0/24", "91.108.4.0/24", "93.158.128.0/24", "95.163.32.0/24",
    "185.76.8.0/24", "185.191.4.0/24", "194.32.72.0/24", "2a00:7360::/32",
    "2a0b:3f80::/32",
]

_FOREIGN_CONF = (
    "create xray_ru_block hash:net family inet maxelem 65536\n"
    "add xray_ru_block 1.2.3.0/24\n"
    "add xray_ru_block 5.6.7.0/24\n"
    "create xray_ru_block6 hash:net family inet6 maxelem 65536\n"
    "add xray_ru_block6 2a01::/32\n"
)


class _EvaporationEnv(unittest.TestCase):
    """Общее окружение: tmp-пути + симулятор ipset + предзаполненный state."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._sim = _IpsetSim()
        self._state = self._tmp / "ipban.json"
        self._snap = self._tmp / "ipban.cidrs"
        self._conf = self._tmp / "ipset.conf"
        self._unit = self._tmp / "xray-ipban-restore.service"
        self._script = self._tmp / "xray-ipban-boot.sh"
        # state с 13 CIDR бана ГРЧЦ (как на Москве в окт.2026)
        self._state.write_text(json.dumps({
            "entries": [{
                "display": "AS61280",
                "kind": "asn",
                "cidrs": _GRCHC_CIDRS,
                "comment": "ГРЧЦ Роскомнадзор DPI-сканер",
                "added_at": "2026-09-01T00:00:00+00:00",
            }]
        }, ensure_ascii=False), encoding="utf-8")
        # персистенс «затёрт сторонним сейвером»: только чужие секции
        self._conf.write_text(_FOREIGN_CONF, encoding="utf-8")
        # живые сеты существуют, но ПУСТЫ (reboot после restore пустоты)
        self._sim.sets = {"xray_manual_ban": set(), "xray_manual_ban6": set()}
        for p in (
            patch("chimera.modules.ipban.subprocess.run", self._sim),
            patch("chimera.modules.ipban._STATE_FILE", self._state),
            patch("chimera.modules.ipban._CIDR_SNAPSHOT", self._snap),
            patch("chimera.modules.ipban._IPSET_CONF", self._conf),
            patch("chimera.modules.ipban._BOOT_UNIT", self._unit),
            patch("chimera.modules.ipban._BOOT_SCRIPT", self._script),
        ):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)


class TestCidrSnapshot(_EvaporationEnv):
    """_state_save → снапшот ipban.cidrs (для boot-скрипта)."""

    def test_snapshot_written_on_state_save(self):
        from chimera.modules.ipban import _state_save
        _state_save({"entries": [{"display": "x", "cidrs": ["1.2.3.0/24", "::/0"]}]} )
        self.assertTrue(self._snap.exists())
        lines = self._snap.read_text(encoding="utf-8").splitlines()
        self.assertIn("1.2.3.0/24", lines)
        self.assertIn("::/0", lines)

    def test_snapshot_empty_for_empty_state(self):
        from chimera.modules.ipban import _state_save
        _state_save({"entries": []})
        content = self._snap.read_text(encoding="utf-8") if self._snap.exists() else ""
        self.assertEqual(content.strip(), "")

    def test_snapshot_dedups_across_entries(self):
        from chimera.modules.ipban import _state_save
        _state_save({"entries": [
            {"display": "a", "cidrs": ["1.2.3.0/24"]},
            {"display": "b", "cidrs": ["1.2.3.0/24", "9.9.9.0/24"]},
        ]})
        lines = self._snap.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sorted(lines), ["1.2.3.0/24", "9.9.9.0/24"])


class TestPersistFromStateUnion(_EvaporationEnv):
    """Персистенс строится из state ∪ live — регрессия тихого испарения."""

    def test_persist_survives_empty_live_set(self):
        """live ПУСТ при 13 CIDR в state → персист обязан содержать все 13."""
        from chimera.modules.ipban import _ipban_persist_save
        _ipban_persist_save()
        text = self._conf.read_text(encoding="utf-8")
        for cidr in _GRCHC_CIDRS:
            name = "xray_manual_ban6" if ":" in cidr else "xray_manual_ban"
            self.assertIn(f"add {name} {cidr}", text,
                          f"CIDR {cidr} выпал из персистенса при пустом live")

    def test_persist_preserves_foreign_sections(self):
        """Чужие секции (xray_ru_block*) сохраняются дословно."""
        from chimera.modules.ipban import _ipban_persist_save
        _ipban_persist_save()
        text = self._conf.read_text(encoding="utf-8")
        self.assertIn("add xray_ru_block 1.2.3.0/24", text)
        self.assertIn("add xray_ru_block6 2a01::/32", text)

    def test_persist_union_with_live_manual_adds(self):
        """Ручной `ipset add` админа (не в state) не теряется при персисте."""
        from chimera.modules.ipban import _ipban_persist_save
        self._sim.sets["xray_manual_ban"].add("100.200.0.0/16")
        _ipban_persist_save()
        text = self._conf.read_text(encoding="utf-8")
        self.assertIn("add xray_manual_ban 100.200.0.0/16", text)
        # state-записи при этом тоже на месте
        self.assertIn(f"add xray_manual_ban {_GRCHC_CIDRS[0]}", text)

    def test_persist_replaces_own_stale_section_no_duplicates(self):
        """Повторный персист не дублирует create-строки собственных секций."""
        from chimera.modules.ipban import _ipban_persist_save
        _ipban_persist_save()
        _ipban_persist_save()
        text = self._conf.read_text(encoding="utf-8")
        self.assertEqual(text.count("create xray_manual_ban "), 1)
        self.assertEqual(text.count("create xray_manual_ban6 "), 1)
        self.assertEqual(text.count("create xray_ru_block "), 1)

    def test_persist_skips_section_when_no_entries_and_no_set(self):
        """Сет не существует и записей нет → секция не пишется вовсе."""
        from chimera.modules.ipban import _ipban_persist_save
        self._sim.sets = {}                      # сеты уничтожены
        self._state.write_text('{"entries": []}', encoding="utf-8")
        _ipban_persist_save()
        text = self._conf.read_text(encoding="utf-8")
        self.assertNotIn("create xray_manual_ban ", text)
        self.assertIn("add xray_ru_block 1.2.3.0/24", text)


class TestIpbanSync(_EvaporationEnv):
    """ipban_sync — идемпотентная конвергенция state → live → персист."""

    def test_sync_refills_live_from_state(self):
        from chimera.modules.ipban import ipban_sync
        self.assertTrue(ipban_sync(quiet=True))
        v4 = {c for c in _GRCHC_CIDRS if ":" not in c}
        v6 = {c for c in _GRCHC_CIDRS if ":" in c}
        self.assertEqual(self._sim.sets["xray_manual_ban"], v4)
        self.assertEqual(self._sim.sets["xray_manual_ban6"], v6)

    def test_sync_rewrites_persist_and_keeps_foreign(self):
        from chimera.modules.ipban import ipban_sync
        ipban_sync(quiet=True)
        text = self._conf.read_text(encoding="utf-8")
        for cidr in _GRCHC_CIDRS:
            name = "xray_manual_ban6" if ":" in cidr else "xray_manual_ban"
            self.assertIn(f"add {name} {cidr}", text)
        self.assertIn("add xray_ru_block 1.2.3.0/24", text)

    def test_sync_idempotent(self):
        from chimera.modules.ipban import ipban_sync
        ipban_sync(quiet=True)
        before = sorted(self._sim.sets["xray_manual_ban"])
        ipban_sync(quiet=True)
        after = sorted(self._sim.sets["xray_manual_ban"])
        self.assertEqual(before, after)

    def test_sync_writes_snapshot_for_legacy_state(self):
        """Деплой фикса на ноду со старым state (без снапшота): sync обязан
        регенерировать ipban.cidrs — иначе бут-самовосстановление инертно."""
        from chimera.modules.ipban import ipban_sync
        self.assertFalse(self._snap.exists())   # старая нода: снапшота нет
        ipban_sync(quiet=True)
        self.assertTrue(self._snap.exists(), "sync не создал снапшот ipban.cidrs")
        lines = set(self._snap.read_text(encoding="utf-8").splitlines())
        self.assertEqual(lines, set(_GRCHC_CIDRS))

    def test_sync_installs_rules_and_boot_unit(self):
        from chimera.modules.ipban import ipban_sync
        ipban_sync(quiet=True)
        inserted = [c for c in self._sim.calls if c[:4] == ["iptables", "-I", "INPUT", "1"]]
        self.assertTrue(inserted, "sync не вставил правило INPUT 1")
        self.assertTrue(self._unit.exists(), "sync не записал boot-юнит")
        self.assertTrue(self._script.exists(), "sync не записал boot-скрипт")

    def test_restore_calls_persist(self):
        """ipban_restore чинит не только live, но и затёртый персистенс."""
        from chimera.modules.ipban import ipban_restore
        ipban_restore()
        text = self._conf.read_text(encoding="utf-8")
        for cidr in _GRCHC_CIDRS:
            name = "xray_manual_ban6" if ":" in cidr else "xray_manual_ban"
            self.assertIn(f"add {name} {cidr}", text)


class TestBootScriptSelfHeal(_EvaporationEnv):
    """Boot-юнит/скрипт восстанавливают ЭЛЕМЕНТЫ из state-снапшота."""

    def test_unit_executes_boot_script(self):
        from chimera.modules.ipban import _ensure_boot_unit, _BOOT_SCRIPT
        _ensure_boot_unit()
        text = self._unit.read_text(encoding="utf-8")
        self.assertIn(f"ExecStart={_BOOT_SCRIPT}", text)
        self.assertIn("After=telemt-iptables.service xray-ipset-restore.service", text)
        self.assertIn("Before=xray.service", text)

    def test_script_refills_entries_from_snapshot(self):
        from chimera.modules.ipban import _ensure_boot_unit, _BOOT_SCRIPT
        _ensure_boot_unit()
        text = self._script.read_text(encoding="utf-8")
        # refill из снапшота (НЕ из /etc/ipset.conf)
        self.assertIn("/var/lib/xray-installer/ipban.cidrs", text)
        self.assertIn("while read -r cidr", text)
        self.assertIn("-exist", text)
        # раздача v4/v6 по наличию двоеточия
        self.assertIn("ipset add xray_manual_ban6", text)
        self.assertIn("ipset add xray_manual_ban ", text)
        # правила — первой строкой INPUT
        self.assertIn("-I INPUT 1", text)

    def test_script_selfheals_ipset_conf(self):
        from chimera.modules.ipban import _ensure_boot_unit
        _ensure_boot_unit()
        text = self._script.read_text(encoding="utf-8")
        self.assertIn("grep -vE", text)
        self.assertIn("ipset save xray_manual_ban", text)
        self.assertIn("mktemp", text)
        self.assertIn("mv -f", text)

    def test_script_is_executable(self):
        from chimera.modules.ipban import _ensure_boot_unit, _BOOT_SCRIPT
        _ensure_boot_unit()
        import stat as _stat
        mode = _BOOT_SCRIPT.stat().st_mode
        self.assertTrue(mode & _stat.S_IXUSR, "boot-скрипт не исполняемый")


if __name__ == "__main__":
    unittest.main(verbosity=2)
