#!/usr/bin/env python3
"""
tests/test_upstream_awg_sync.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/scripts/upstream_awg_sync.py (дев-инструмент синка
Химеры с апстримом bivlked/amneziawg-installer).

Покрывает (офлайн, без сети — только чистые функции на фикстурах):
  1. parse_tag / tags_after — семвер-хронология тегов
  2. extract_changelog_sections — секции CHANGELOG.md апстрима
  3. classify_path — карта «файл апстрима → цель в Химере»
  4. validate_ru_zone — валидация снимка РФ-подсетей
  5. render_report — структура отчёта
  6. Контракт маркера AWGS_UPSTREAM_SYNCED_TAG в awg_constants.py
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _load_sync_module():
    """Скрипт лежит в chimera/scripts/ без __init__ — грузим по пути."""
    mod_path = _PROJECT_ROOT / "chimera" / "scripts" / "upstream_awg_sync.py"
    spec = importlib.util.spec_from_file_location(
        "upstream_awg_sync_test", mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SYNC = _load_sync_module()


class TestParseTag(unittest.TestCase):
    """parse_tag / tags_after — семвер-хронология."""

    def test_parse(self):
        self.assertEqual(_SYNC.parse_tag("v6.3.9"), (6, 3, 9))
        self.assertEqual(_SYNC.parse_tag("6.3.9"), (6, 3, 9))
        self.assertIsNone(_SYNC.parse_tag("arm-packages"))
        self.assertIsNone(_SYNC.parse_tag("v4.0"))
        self.assertIsNone(_SYNC.parse_tag("v6"))

    def test_version_ordering(self):
        """v6.10.0 > v6.3.9 > v6.3.10 НЕ по строкам, а по tuple."""
        self.assertGreater(_SYNC.parse_tag("v6.10.0"),
                           _SYNC.parse_tag("v6.3.9"))
        self.assertGreater(_SYNC.parse_tag("v6.3.10"),
                           _SYNC.parse_tag("v6.3.9"))

    def test_tags_after(self):
        tags = ["v6.3.5", "v6.3.8", "v6.3.9", "v6.4.0", "arm-packages",
                "v6.2.2"]
        self.assertEqual(_SYNC.tags_after(tags, "v6.3.8"),
                         ["v6.3.9", "v6.4.0"])
        # synced не семверный — хронология не строится (пусто)
        self.assertEqual(_SYNC.tags_after(tags, "junk"), [])
        # Всё свежее synced — пусто
        self.assertEqual(_SYNC.tags_after(tags, "v6.4.0"), [])


class TestExtractChangelogSections(unittest.TestCase):
    """extract_changelog_sections — формат '## [X.Y.Z] …' апстрима."""

    _FIXTURE = """# Changelog

## [Unreleased]

### Документация

- Драфт.

## [6.4.0] - 2026-12-01

**v6.4.0** - новая секция апстрима.

### Исправлено

- Фикс раз.

## [6.3.9] - 2026-11-23

**v6.3.9** - старая секция.

## [6.3.8] - 2026-11-22

Старее.
"""

    def test_extracts_only_requested(self):
        got = _SYNC.extract_changelog_sections(
            self._FIXTURE, ["6.4.0", "6.3.9"])
        self.assertEqual(sorted(got), ["6.3.9", "6.4.0"])
        self.assertIn("Фикс раз.", got["6.4.0"])
        self.assertIn("v6.3.9", got["6.3.9"])
        self.assertNotIn("6.3.8", got)

    def test_missing_version_absent(self):
        got = _SYNC.extract_changelog_sections(self._FIXTURE, ["9.9.9"])
        self.assertEqual(got, {})


class TestClassifyPath(unittest.TestCase):
    """classify_path — карта «файл апстрима → цель в Химере»."""

    def test_ru_zone_is_auto(self):
        verdict, _ = _SYNC.classify_path("cascade/ru.zone")
        self.assertEqual(verdict, "auto")

    def test_cascade_other_is_port(self):
        verdict, target = _SYNC.classify_path("cascade/awg-routing.sh")
        self.assertEqual(verdict, "port")
        self.assertIn("awg_cascade", target)

    def test_core_scripts_are_port(self):
        for f in ("install_amneziawg.sh", "awg_common.sh",
                  "manage_amneziawg.sh"):
            verdict, target = _SYNC.classify_path(f)
            self.assertEqual(verdict, "port", msg=f)
            self.assertIn("chimera/modules", target)

    def test_docs_ignored(self):
        for f in ("README.md", "ADVANCED.md", "CASCADE.md", "docs/x.md",
                  "signing/k.txt", "tests/t.sh", "KEYS.txt", "logo.jpg"):
            verdict, _ = _SYNC.classify_path(f)
            self.assertEqual(verdict, "ignore", msg=f)

    def test_unknown_file_is_port_with_note(self):
        verdict, target = _SYNC.classify_path("brand_new_module.go")
        self.assertEqual(verdict, "port")
        self.assertIn("глянуть вручную", target)


class TestValidateRuZone(unittest.TestCase):
    """validate_ru_zone — валидация снимка ipdeny."""

    def test_valid_snapshot(self):
        body = "\n".join(f"10.{i // 250 % 250}.{i % 250}.0/24"
                         for i in range(8100))
        ok, n, err = _SYNC.validate_ru_zone(body.encode())
        self.assertTrue(ok, msg=err)
        self.assertEqual(n, 8100)

    def test_garbage_line_rejected(self):
        body = "\n".join(["1.2.3.0/24"] * 8100 + ["hello world"])
        ok, _, err = _SYNC.validate_ru_zone(body.encode())
        self.assertFalse(ok)
        self.assertIn("не CIDR", err)

    def test_too_few_subnets_rejected(self):
        """< 8000 подсетей — файл битый/неполный (исторически 8600-8800)."""
        body = "\n".join(["1.2.3.0/24"] * 100)
        ok, n, _ = _SYNC.validate_ru_zone(body.encode())
        self.assertFalse(ok)
        self.assertEqual(n, 100)

    def test_not_utf8_rejected(self):
        ok, _, _ = _SYNC.validate_ru_zone(b"\\xff\\xfe\\x00binary")
        self.assertFalse(ok)


class TestRenderReport(unittest.TestCase):
    """render_report — структура отчёта."""

    def test_up_to_date(self):
        rep = _SYNC.build_report("v6.3.9", "v6.3.9", [], {}, [])
        text = _SYNC.render_report(rep)
        self.assertIn("Новых версий нет", text)
        self.assertFalse(rep["needs_port"])

    def test_new_version_with_port_target(self):
        rep = _SYNC.build_report(
            "v6.3.9", "v6.4.0", ["v6.4.0"],
            {"6.4.0": "**v6.4.0** - правка генератора."},
            ["awg_common.sh", "README.md"])
        text = _SYNC.render_report(rep)
        self.assertIn("v6.4.0", text)
        self.assertIn("awg_common.sh", text)
        self.assertIn("порт-анализ", text)
        self.assertTrue(rep["needs_port"])
        self.assertFalse(rep["ru_zone_changed"])

    def test_ru_zone_changed_flag(self):
        rep = _SYNC.build_report(
            "v6.3.9", "v6.4.0", ["v6.4.0"], {},
            ["cascade/ru.zone", "README.md"])
        self.assertTrue(rep["ru_zone_changed"])
        text = _SYNC.render_report(rep)
        self.assertIn("--apply-ru-zone", text)


class TestSyncedMarkerContract(unittest.TestCase):
    """Маркер AWGS_UPSTREAM_SYNCED_TAG — единая точка правды синка."""

    def test_marker_is_semver_and_fresh(self):
        """Маркер — валидный vX.Y.Z; скрипт его читает и сравнивает."""
        from chimera.modules.awg_constants import AWGS_UPSTREAM_SYNCED_TAG
        self.assertIsNotNone(_SYNC.parse_tag(AWGS_UPSTREAM_SYNCED_TAG),
                             msg="AWGS_UPSTREAM_SYNCED_TAG обязан быть "
                                 "семвер-тегом вида v6.3.9")
        self.assertTrue(AWGS_UPSTREAM_SYNCED_TAG.startswith("v"))
        # Скрипт и константа согласны (импорт в скрипте — из того же места)
        self.assertEqual(_SYNC.AWGS_UPSTREAM_SYNCED_TAG,
                         AWGS_UPSTREAM_SYNCED_TAG)

    def test_file_targets_cover_core_scripts(self):
        """Карта классификации знает все 3 скрипта апстрима + cascade."""
        srcs = [p for p, _, _ in _SYNC.FILE_TARGETS]
        for core in ("install_amneziawg.sh", "awg_common.sh",
                     "manage_amneziawg.sh", "cascade/"):
            self.assertIn(core, srcs, msg=f"{core} нет в FILE_TARGETS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
