#!/usr/bin/env python3
"""
tests/test_ip_mask.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты wildcard-масок IP (фича ipmask-1): 176.9.*.* → 176.9.0.0/16.

Покрывает:
  1. ip_mask.mask_to_cidr — правила масок (хвостовые звёздочки, запреты)
  2. ip_mask.ip_in_entries — CIDR-containment для autoban/scan
  3. user_ip_whitelist._validate_ip_or_cidr — маски на входе порталов/TUI
  4. ipban._detect_input_kind/_parse_mask — классификатор и парсер банов
  5. remote-cmd _normalize_ip_input — двойник в standalone-скрипте
  6. autoban._whitelist_add_many — whitelist с CIDR/масками
  7. Инвариант «нет хардкода»: произвольные октеты (152.65/189.122/…)

Принцип: примеры из запроса (176.9.*.*, 152.65.*.*, 189.122.*.*) — НЕ
догма и не хардкод: любое значение октетов 0-255 должно работать.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# Путь к standalone-скрипту (он не в пакете — импортируем по файлу)
_REMOTE_CMD_PATH = _PROJECT_ROOT / "scripts" / "chimera-remote-cmd.py"


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


# ══════════════════════════════════════════════════════════════════════════════
#  1. mask_to_cidr — канонические правила
# ══════════════════════════════════════════════════════════════════════════════

class TestMaskToCidr(unittest.TestCase):
    """mask_to_cidr — нормализация масок в CIDR."""

    def setUp(self):
        from chimera.modules import ip_mask
        self.ip_mask = ip_mask

    def test_two_trailing_octets(self):
        """176.9.*.* → 176.9.0.0/16 (пример из запроса пользователя)."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.9.*.*")
        self.assertTrue(ok, err)
        self.assertEqual(cidr, "176.9.0.0/16")

    def test_other_octets_not_dogma(self):
        """Примеры владельца 152.65.*.* и 189.122.*.* — любые октеты."""
        for mask, want in [
            ("152.65.*.*", "152.65.0.0/16"),
            ("189.122.*.*", "189.122.0.0/16"),
            ("46.17.*.*", "46.17.0.0/16"),
            ("5.167.*.*", "5.167.0.0/16"),
        ]:
            ok, cidr, err = self.ip_mask.mask_to_cidr(mask)
            self.assertTrue(ok, f"{mask}: {err}")
            self.assertEqual(cidr, want)

    def test_one_trailing_octet(self):
        """176.9.* — сокращение от 176.9.*.* (звёздочка «до конца адреса")."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.9.*")
        self.assertTrue(ok, err)
        self.assertEqual(cidr, "176.9.0.0/16")

    def test_three_trailing_octets(self):
        """176.* → 176.0.0.0/8; 176.*.* — то же самое."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.*")
        self.assertTrue(ok, err)
        self.assertEqual(cidr, "176.0.0.0/8")
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.*.*")
        self.assertTrue(ok, err)
        self.assertEqual(cidr, "176.0.0.0/8")

    def test_last_octet_only(self):
        """a.b.c.* → /24 (звёздочка ровно в последнем октете)."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.9.40.*")
        self.assertTrue(ok, err)
        self.assertEqual(cidr, "176.9.40.0/24")

    def test_full_short_form(self):
        """Сокращённая форма без звёздочек не маска — ошибка «нет звёздочек»."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.9.7.5")
        self.assertFalse(ok)
        self.assertIn("звёздочек", err)

    def test_all_wildcard_forbidden(self):
        """*.*.*.* = 0.0.0.0/0 = весь интернет — запрет."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("*.*.*.*")
        self.assertFalse(ok)
        self.assertIn("запрещена", err)

    def test_middle_wildcard_forbidden(self):
        """Звёздочка в середине (176.*.9.1) — запрет с понятной ошибкой."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176.*.9.1")
        self.assertFalse(ok)
        self.assertIn("ПОСЛЕДНИХ", err)

    def test_leading_wildcard_forbidden(self):
        """Ведущая звёздочка (*.9.8.7) — запрет."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("*.9.8.7")
        self.assertFalse(ok)

    def test_double_dot_typo_rejected_with_hint(self):
        """Опечатка 176..9.*.* (из исходного запроса) — отказ с подсказкой."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("176..9.*.*")
        self.assertFalse(ok)
        self.assertIn("176.9.*.*", err)  # подсказка правильной формы

    def test_octet_over_255(self):
        ok, cidr, err = self.ip_mask.mask_to_cidr("300.9.*.*")
        self.assertFalse(ok)
        self.assertIn("255", err)

    def test_ipv6_mask_rejected(self):
        """IPv6-маски не поддерживаются — документированный отказ."""
        ok, cidr, err = self.ip_mask.mask_to_cidr("2001:db8::*")
        self.assertFalse(ok)
        self.assertIn("IPv6", err)

    def test_too_many_octets(self):
        ok, cidr, err = self.ip_mask.mask_to_cidr("1.2.3.4.*.*")
        self.assertFalse(ok)

    def test_strip_whitespace(self):
        ok, cidr, err = self.ip_mask.mask_to_cidr("  176.9.*.*  ")
        self.assertTrue(ok, err)
        self.assertEqual(cidr, "176.9.0.0/16")

    def test_is_wildcard_mask(self):
        self.assertTrue(self.ip_mask.is_wildcard_mask("176.9.*.*"))
        self.assertTrue(self.ip_mask.is_wildcard_mask("176.*"))
        self.assertFalse(self.ip_mask.is_wildcard_mask("1.2.3.4"))
        self.assertFalse(self.ip_mask.is_wildcard_mask("10.0.0.0/24"))
        self.assertFalse(self.ip_mask.is_wildcard_mask("2001:db8::*"))


# ══════════════════════════════════════════════════════════════════════════════
#  2. ip_in_entries — CIDR-containment
# ══════════════════════════════════════════════════════════════════════════════

class TestIpInEntries(unittest.TestCase):
    """ip_in_entries — замена точечного сравнения whitelist."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules.ip_mask import ip_in_entries
        self.ip_in_entries = ip_in_entries

    def test_exact_match(self):
        self.assertTrue(self.ip_in_entries("10.0.0.1", ["10.0.0.1", "8.8.8.8"]))

    def test_cidr_containment(self):
        """176.9.0.0/16 накрывает 176.9.5.5 — суть фичи."""
        self.assertTrue(self.ip_in_entries("176.9.5.5", ["176.9.0.0/16"]))
        self.assertTrue(self.ip_in_entries("176.9.255.254", ["176.9.0.0/16"]))

    def test_cidr_no_containment(self):
        self.assertFalse(self.ip_in_entries("176.10.5.5", ["176.9.0.0/16"]))

    def test_mixed_entries(self):
        wl = ["8.8.8.8", "176.9.0.0/16", "2001:db8::/32", "мусор"]
        self.assertTrue(self.ip_in_entries("176.9.7.7", wl))
        self.assertTrue(self.ip_in_entries("8.8.8.8", wl))
        self.assertFalse(self.ip_in_entries("1.2.3.4", wl))

    def test_ipv6_containment(self):
        self.assertTrue(self.ip_in_entries("2001:db8::1", ["2001:db8::/32"]))
        self.assertFalse(self.ip_in_entries("2001:db9::1", ["2001:db8::/32"]))

    def test_v4_addr_not_in_v6_net(self):
        self.assertFalse(self.ip_in_entries("1.2.3.4", ["::/0"]))

    def test_garbage_entries_ignored(self):
        self.assertFalse(self.ip_in_entries("1.2.3.4", ["", "not-an-ip", None, 42]))

    def test_empty(self):
        self.assertFalse(self.ip_in_entries("1.2.3.4", []))
        self.assertFalse(self.ip_in_entries("", ["1.2.3.4"]))


# ══════════════════════════════════════════════════════════════════════════════
#  3. user_ip_whitelist — единая точка валидации порталов/TUI
# ══════════════════════════════════════════════════════════════════════════════

class TestUserIpWhitelistMask(unittest.TestCase):
    """_validate_ip_or_cidr принимает маски и нормализует в CIDR."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _v(self, value):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        return _validate_ip_or_cidr(value)

    def test_mask_normalizes_to_cidr(self):
        ok, norm, err = self._v("176.9.*.*")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "176.9.0.0/16")

    def test_mask_arbitrary_octets(self):
        ok, norm, err = self._v("152.65.*.*")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "152.65.0.0/16")
        ok, norm, err = self._v("189.122.*")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "189.122.0.0/16")

    def test_mask_24(self):
        ok, norm, err = self._v("176.9.40.*")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "176.9.40.0/24")

    def test_mask_8(self):
        ok, norm, err = self._v("45.*")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "45.0.0.0/8")

    def test_private_mask_rejected(self):
        """Маска приватного диапазона — запрет, как и точный приватный IP."""
        ok, norm, err = self._v("10.*")
        self.assertFalse(ok)
        self.assertIn("Приватный", err)
        ok, norm, err = self._v("192.168.*.*")
        self.assertFalse(ok)

    def test_loopback_mask_rejected(self):
        ok, norm, err = self._v("127.*")
        self.assertFalse(ok)
        self.assertIn("Loopback", err)

    def test_bad_mask_rejected(self):
        ok, norm, err = self._v("*.*.*.*")
        self.assertFalse(ok)
        ok, norm, err = self._v("176.*.9.1")
        self.assertFalse(ok)

    def test_plain_ip_still_ok(self):
        ok, norm, err = self._v("5.6.7.8")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "5.6.7.8")

    def test_cidr_still_ok(self):
        ok, norm, err = self._v("5.6.7.0/24")
        self.assertTrue(ok, err)
        self.assertEqual(norm, "5.6.7.0/24")


# ══════════════════════════════════════════════════════════════════════════════
#  4. ipban — классификатор и парсер
# ══════════════════════════════════════════════════════════════════════════════

class TestIpbanMask(unittest.TestCase):
    """ipban: kind='mask' + _parse_mask + _resolve_to_cidrs."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_detect_kind_mask(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("176.9.*.*"), "mask")
        self.assertEqual(_detect_input_kind("176.*"), "mask")

    def test_parse_mask(self):
        from chimera.modules.ipban import _parse_mask
        self.assertEqual(_parse_mask("176.9.*.*"), ["176.9.0.0/16"])
        self.assertEqual(_parse_mask("152.65.*.*"), ["152.65.0.0/16"])

    def test_parse_mask_rejects_garbage(self):
        from chimera.modules.ipban import _parse_mask
        with self.assertRaises(ValueError):
            _parse_mask("176.*.9.1")
        with self.assertRaises(ValueError):
            _parse_mask("*.*.*.*")

    def test_resolve_to_cidrs_mask(self):
        from chimera.modules.ipban import _resolve_to_cidrs
        display, kind, cidrs = _resolve_to_cidrs("189.122.*.*")
        self.assertEqual(kind, "mask")
        self.assertEqual(display, "189.122.0.0/16")
        self.assertEqual(cidrs, ["189.122.0.0/16"])


# ══════════════════════════════════════════════════════════════════════════════
#  5. remote-cmd — двойник нормализации (standalone)
# ══════════════════════════════════════════════════════════════════════════════

class TestRemoteCmdNormalize(unittest.TestCase):
    """scripts/chimera-remote-cmd.py: _normalize_ip_input — двойник ip_mask."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "chimera_remote_cmd_test", _REMOTE_CMD_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.mod = mod

    def test_masks(self):
        n = self.mod._normalize_ip_input
        self.assertEqual(n("176.9.*.*"), "176.9.0.0/16")
        self.assertEqual(n("152.65.*.*"), "152.65.0.0/16")
        self.assertEqual(n("189.122.*"), "189.122.0.0/16")
        self.assertEqual(n("176.9.40.*"), "176.9.40.0/24")
        self.assertEqual(n("45.*"), "45.0.0.0/8")

    def test_ip_and_cidr_passthrough(self):
        n = self.mod._normalize_ip_input
        self.assertEqual(n("1.2.3.4"), "1.2.3.4")
        self.assertEqual(n("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(n("2001:db8::1"), "2001:db8::1")
        self.assertEqual(n("2001:db8::/32"), "2001:db8::/32")

    def test_rejections(self):
        n = self.mod._normalize_ip_input
        self.assertIsNone(n("*.*.*.*"))
        self.assertIsNone(n("176.*.9.1"))
        self.assertIsNone(n("176..9.*.*"))
        self.assertIsNone(n("300.1.*.*"))
        self.assertIsNone(n("не-ip"))
        self.assertIsNone(n(""))
        self.assertIsNone(n("2001:db8::*"))

    def test_validate_ip_alias(self):
        v = self.mod._validate_ip
        self.assertTrue(v("1.2.3.4"))
        self.assertTrue(v("176.9.*.*"))
        self.assertFalse(v("мусор"))

    def test_ban_set_dispatch(self):
        m = self.mod
        self.assertEqual(m._ban_set_for("1.2.3.4"), m.BAN_V4)
        self.assertEqual(m._ban_set_for("176.9.0.0/16"), m.BAN_V4)
        self.assertEqual(m._ban_set_for("2001:db8::/32"), m.BAN_V6)
        self.assertEqual(m._wl_set_for("176.9.0.0/16"), m.WL_V4)
        self.assertEqual(m._wl_set_for("2001:db8::/32"), m.WL_V6)

    def test_parse_member_line_cidr(self):
        """Члены ipset — IP и CIDR (баг #2: банлист не показывал CIDR)."""
        p = self.mod._parse_member_line
        self.assertEqual(p("1.2.3.4"), ("1.2.3.4", False))
        self.assertEqual(p("176.9.0.0/16"), ("176.9.0.0/16", False))
        self.assertEqual(p("2001:db8::/32"), ("2001:db8::/32", True))
        self.assertIsNone(p("Name: xray_manual_ban"))
        self.assertIsNone(p("members:"))
        self.assertIsNone(p(""))

    def test_wl_sets_are_current_names(self):
        """Баг #1: имена сетей = clients_wl_v4/v6 (не старый clients_wl)."""
        self.assertEqual(self.mod.WL_V4, "clients_wl_v4")
        self.assertEqual(self.mod.WL_V6, "clients_wl_v6")
        self.assertEqual(self.mod.BAN_V4, "xray_manual_ban")
        self.assertEqual(self.mod.BAN_V6, "xray_manual_ban6")


# ══════════════════════════════════════════════════════════════════════════════
#  6. autoban — whitelist с CIDR/масками
# ══════════════════════════════════════════════════════════════════════════════

class TestAutobanWhitelistMany(unittest.TestCase):
    """_whitelist_add_many: маски/CIDR принимаются и нормализуются."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_mask_normalized(self):
        from chimera.modules.autoban import _whitelist_add_many
        wl = []
        added, warns = _whitelist_add_many(wl, "176.9.*.*")
        self.assertEqual(added, ["176.9.0.0/16"])
        self.assertEqual(wl, ["176.9.0.0/16"])
        self.assertEqual(warns, [])

    def test_mixed_tokens(self):
        from chimera.modules.autoban import _whitelist_add_many
        wl = []
        added, warns = _whitelist_add_many(wl, "8.8.8.8, 152.65.*.* 2001:db8::/32")
        self.assertEqual(added, ["8.8.8.8", "152.65.0.0/16", "2001:db8::/32"])
        self.assertEqual(warns, [])

    def test_cidr_now_supported(self):
        """Кейс <node-2> закрыт: CIDR больше не отклоняется."""
        from chimera.modules.autoban import _whitelist_add_many
        wl = []
        added, warns = _whitelist_add_many(wl, "203.0.113.0/24")
        self.assertEqual(added, ["203.0.113.0/24"])
        self.assertEqual(warns, [])

    def test_garbage_warned(self):
        from chimera.modules.autoban import _whitelist_add_many
        wl = []
        added, warns = _whitelist_add_many(wl, "мусор, 176.*.9.1, *.*.*.*")
        self.assertEqual(added, [])
        self.assertEqual(len(warns), 3)

    def test_duplicate_warned(self):
        from chimera.modules.autoban import _whitelist_add_many
        wl = ["176.9.0.0/16"]
        added, warns = _whitelist_add_many(wl, "176.9.*.*")
        self.assertEqual(added, [])
        self.assertEqual(len(warns), 1)


# ══════════════════════════════════════════════════════════════════════════════
#  7. Инвариант: ноль хардкода конкретных адресов
# ══════════════════════════════════════════════════════════════════════════════

class TestNoHardcodedAddresses(unittest.TestCase):
    """В ip_mask.py не должно быть хардкода конкретных префиксов.

    Примеры 176.9/152.65/189.122 — только в докстрингах/подсказках,
    логика обязана работать с любыми октетами.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_random_octets_work(self):
        import random
        from chimera.modules.ip_mask import mask_to_cidr
        random.seed(42)
        for _ in range(200):
            a = random.randint(1, 223)
            while a in (10, 127, 172, 192, 169, 224):  # уходим от приватных
                a = random.randint(1, 223)
            b = random.randint(0, 255)
            mask = f"{a}.{b}.*.*"
            ok, cidr, err = mask_to_cidr(mask)
            self.assertTrue(ok, f"{mask}: {err}")
            self.assertEqual(cidr, f"{a}.{b}.0.0/16")

    def test_no_address_literals_in_code(self):
        """В логике сравнений ip_mask.py — только структурные константы.

        Допустимые int-литералы в сравнениях: 0/1/2/3/4 (октеты, версии),
        8 (бит в октете), 255 (лимит октета). Любой другой числовой литерал
        в условии = подозрение на хардкод адреса.
        """
        import ast
        src = (_PROJECT_ROOT / "chimera" / "modules" / "ip_mask.py").read_text()
        tree = ast.parse(src)
        allowed = {0, 1, 2, 3, 4, 8, 255}
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for side in [node.left] + node.comparators:
                    if isinstance(side, ast.Constant) and isinstance(side.value, int):
                        self.assertIn(
                            side.value, allowed,
                            f"Хардкод-подозрение: {side.value} в условии "
                            f"(строка {side.lineno})")


if __name__ == "__main__":
    unittest.main(verbosity=2)
