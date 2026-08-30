# -*- coding: utf-8 -*-
"""
v70 (stale-mirror-guard): защита от устаревших кэшей зеркал при установке Xray.

Первопричина инцидента 28-29.08 (сервер vds13216, Режим B «мёртв» при живом
Mode-профиле): установщик получил от ghproxy.net ЗАКЭШИРОВАННЫЙ ответ
/releases/latest = v26.3.27 (реальный latest на тот момент — v26.7.28) и
самосогласованно скачал всё по старому тегу (zip + SHA256 совпали — они же
для одного тега). На сервере осел бинарник на 4 месяца старее. В 26.3.27
новейший uTLS-отпечаток firefox = Firefox 120 (2023!) → на международном
плече RU→зарубеж ТСПУ/DPI рвал REALITY-хендшейк entry→exit (30-секундный
таймаут = tcpUserTimeout из sockopt), при живом обычном TLS/ping/DNS.
Рабочий сервер на v26.7.28 (Firefox 148) проходил DPI без проблем.

Проверяемое:
  1. _max_version_tag: выбор максимального тега (анти-stale).
  2. Сбор тегов со ВСЕХ зеркал (не первый ответ).
  3. Юнит-файл: Environment=XRAY_LOCATION_ASSET (systemd-валидная форма;
     форма с точками молча отбрасывается systemd — баг v68).
  4. Пост-установочная сверка версии бинарника с ожидаемой.
"""
import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# ═════════════════════════════════════════════════════════════════════════════
#  1. _max_version_tag
# ═════════════════════════════════════════════════════════════════════════════
class TestMaxVersionTag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "xray_install.py").read_text()
        ns = {"re": re}
        exec(compile(
            src[src.index("def _max_version_tag"):src.index("def install_xray")],
            "<t>", "exec"), ns)
        cls.fn = staticmethod(ns["_max_version_tag"])

    def test_prefers_newer(self):
        self.assertEqual(
            self.fn(["v26.3.27", "v26.7.28"]), "v26.7.28")

    def test_order_independent(self):
        self.assertEqual(
            self.fn(["v26.7.28", "v26.3.27"]), "v26.7.28")

    def test_multidigit_minor(self):
        self.assertEqual(
            self.fn(["v26.10.3", "v26.9.1"]), "v26.10.3")

    def test_patch_compare(self):
        self.assertEqual(
            self.fn(["v1.2.3", "v1.2.10"]), "v1.2.10")

    def test_ignores_garbage(self):
        self.assertEqual(
            self.fn(["garbage", "", "v26.1.1"]), "v26.1.1")

    def test_all_garbage_empty(self):
        self.assertEqual(self.fn(["x", "", None]), "")

    def test_no_v_prefix(self):
        self.assertEqual(
            self.fn(["26.3.27", "26.7.28"]), "26.7.28")


# ═════════════════════════════════════════════════════════════════════════════
#  2. Сбор тегов со всех зеркал (структура кода)
# ═════════════════════════════════════════════════════════════════════════════
class TestMirrorCollection(unittest.TestCase):
    def test_collects_all_mirrors_no_early_break(self):
        """Теги собираются со ВСЕХ зеркал: нет break по первому успеху
        внутри цикла по _API_MIRRORS (v70)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "xray_install.py").read_text()
        # фрагмент цикла v70
        seg = src[src.index("_collected_tags: list = []"):
                  src.index("Шаг B: stable недоступен")]
        self.assertIn("_collected_tags.append(_tag)", seg)
        self.assertNotIn("if latest_tag:\n                            break",
                         seg)
        self.assertIn("_max_version_tag(_collected_tags)", seg)

    def test_version_check_after_install(self):
        """Пост-установочная сверка версии бинарника с latest_tag."""
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "xray_install.py").read_text()
        self.assertIn("_real_ver != _want_ver", src)
        self.assertIn("ВНИМАНИЕ: установлен Xray", src)


# ═════════════════════════════════════════════════════════════════════════════
#  3. Юнит-файл: валидная форма env-переменной
# ═════════════════════════════════════════════════════════════════════════════
class TestUnitEnvForm(unittest.TestCase):
    def test_env_line_uses_underscores(self):
        """systemd отвергает имена с точками (Invalid environment
        assignment) — юнит обязан использовать XRAY_LOCATION_ASSET."""
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "xray_install.py").read_text()
        self.assertIn(
            '_geo_env_line = "Environment=XRAY_LOCATION_ASSET=/etc/xray"',
            src)
        # старая форма больше не должна встречаться в присваивании
        self.assertNotIn(
            '_geo_env_line = "Environment=xray.location.asset=/etc/xray"',
            src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
