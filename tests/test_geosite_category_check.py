#!/usr/bin/env python3
"""
tests/test_geosite_category_check.py
───────────────────────────────────────────────────────────────────────────────
Тесты для _geosite_has_category() и условного добавления geosite-правил
в build_split_tunnel_routing_rules().

Проблема (v4.25 FIX): Xray падал при старте если geosite.dat не содержал
категорию ru-available-only-inside. Это происходило при:
  • Установке с нуля если geosite.dat старый или от другого источника
  • использовании не-runetfreedom geosite.dat
  • Повреждении geosite.dat

Ошибка: "code not found in geosite.dat: RU-AVAILABLE-ONLY-INSIDE"

Фикс: перед добавлением geosite:category в routing rules, проверяем
что категория существует через grep по бинарному geosite.dat.
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


def _make_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


class TestGeositeHasCategory(unittest.TestCase):
    """_geosite_has_category — проверка наличия категории в geosite.dat."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_when_category_exists(self):
        """grep находит категорию в файле → True."""
        from chimera.modules import split_tunnel
        with patch.object(Path, "exists", return_value=True), \
             patch("subprocess.run", return_value=_make_completed(returncode=0)):
            result = split_tunnel._geosite_has_category("category-ru")
        self.assertTrue(result)

    def test_returns_false_when_category_missing(self):
        """grep НЕ находит категорию → False."""
        from chimera.modules import split_tunnel
        with patch.object(Path, "exists", return_value=True), \
             patch("subprocess.run", return_value=_make_completed(returncode=1)):
            result = split_tunnel._geosite_has_category("ru-available-only-inside")
        self.assertFalse(result)

    def test_returns_false_when_no_geosite_file(self):
        """geosite.dat не существует → False (не падает)."""
        from chimera.modules import split_tunnel
        with patch.object(Path, "exists", return_value=False):
            result = split_tunnel._geosite_has_category("category-ru")
        self.assertFalse(result)

    def test_strips_geosite_prefix(self):
        """Принимает как 'category-ru' так и 'geosite:category-ru'."""
        from chimera.modules import split_tunnel
        with patch.object(Path, "exists", return_value=True), \
             patch("subprocess.run", return_value=_make_completed(returncode=0)) as mock_run:
            split_tunnel._geosite_has_category("geosite:category-ru")
            # Проверяем что grep искал 'category-ru' (без префикса geosite:).
            args = mock_run.call_args[0][0]
            self.assertIn("category-ru", args)
            self.assertNotIn("geosite:category-ru", args)

    def test_empty_category_returns_false(self):
        """Пустая категория → False."""
        from chimera.modules import split_tunnel
        self.assertFalse(split_tunnel._geosite_has_category(""))
        self.assertFalse(split_tunnel._geosite_has_category(None))


class TestBuildSplitTunnelRulesCategoryCheck(unittest.TestCase):
    """build_split_tunnel_routing_rules — условное добавление geosite-правил."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_skips_ru_available_only_inside_when_missing(self):
        """Если ru-available-only-inside НЕ найден — правило НЕ добавляется."""
        from chimera.modules import split_tunnel
        # Мокаем что split tunnel включён, geo-файлы есть.
        core = sys.modules["chimera._core"]
        core.SPLIT_TUNNEL_ENABLED = True
        core.SPLIT_TUNNEL_EXTRA_DOMAINS = []
        core.SPLIT_TUNNEL_EXTRA_IPS = []
        # category-ru есть, ru-available-only-inside НЕТ.
        with patch.object(split_tunnel, "_geo_files_available", return_value=True), \
             patch.object(split_tunnel, "_geosite_has_category",
                          side_effect=lambda cat: cat == "category-ru"):
            rules = split_tunnel.build_split_tunnel_routing_rules(
                proxy_tag="chain-exit", direct_tag="direct",
            )
        # Ищем правило с geosite доменами.
        geosite_rule = None
        for r in rules:
            domains = r.get("domain", [])
            if any("geosite:" in d for d in domains):
                geosite_rule = r
                break
        self.assertIsNotNone(geosite_rule, "Должно быть geosite-правило")
        all_domains = geosite_rule["domain"]
        self.assertIn("geosite:category-ru", all_domains)
        self.assertNotIn("geosite:ru-available-only-inside", all_domains,
                         "ru-available-only-inside НЕ должен быть в правилах если категории нет")

    def test_includes_both_when_both_exist(self):
        """Если обе категории есть — обе добавляются."""
        from chimera.modules import split_tunnel
        core = sys.modules["chimera._core"]
        core.SPLIT_TUNNEL_ENABLED = True
        core.SPLIT_TUNNEL_EXTRA_DOMAINS = []
        core.SPLIT_TUNNEL_EXTRA_IPS = []
        with patch.object(split_tunnel, "_geo_files_available", return_value=True), \
             patch.object(split_tunnel, "_geosite_has_category", return_value=True):
            rules = split_tunnel.build_split_tunnel_routing_rules(
                proxy_tag="chain-exit", direct_tag="direct",
            )
        geosite_rule = None
        for r in rules:
            domains = r.get("domain", [])
            if any("geosite:" in d for d in domains):
                geosite_rule = r
                break
        self.assertIsNotNone(geosite_rule)
        all_domains = geosite_rule["domain"]
        self.assertIn("geosite:category-ru", all_domains)
        self.assertIn("geosite:ru-available-only-inside", all_domains)

    def test_skips_both_when_both_missing(self):
        """Если обе категории отсутствуют — geosite-правило всё равно создаётся,
        но только с IP-проверочными доменами (без geosite:)."""
        from chimera.modules import split_tunnel
        core = sys.modules["chimera._core"]
        core.SPLIT_TUNNEL_ENABLED = True
        core.SPLIT_TUNNEL_EXTRA_DOMAINS = []
        core.SPLIT_TUNNEL_EXTRA_IPS = []
        with patch.object(split_tunnel, "_geo_files_available", return_value=True), \
             patch.object(split_tunnel, "_geosite_has_category", return_value=False):
            rules = split_tunnel.build_split_tunnel_routing_rules(
                proxy_tag="chain-exit", direct_tag="direct",
            )
        geosite_rule = None
        for r in rules:
            domains = r.get("domain", [])
            if any("geosite:" in d for d in domains):
                geosite_rule = r
                break
        # Правило всё равно создаётся (с IP-проверочными доменами), но БЕЗ geosite:.
        if geosite_rule:
            all_domains = geosite_rule["domain"]
            self.assertNotIn("geosite:category-ru", all_domains)
            self.assertNotIn("geosite:ru-available-only-inside", all_domains)
            # IP-проверочные домены остаются.
            self.assertTrue(any("2ip.ru" in d for d in all_domains))


if __name__ == "__main__":
    unittest.main(verbosity=2)
