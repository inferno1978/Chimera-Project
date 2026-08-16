#!/usr/bin/env python3
"""
tests/test_singbox_client_rulesets.py
───────────────────────────────────────────────────────────────────────────────
Тесты для модуля chimera/modules/singbox_client_rulesets.py.

Покрываем:
  1. Каталог RULESET_CATALOG — корректность URL'ов (правильное имя репо).
  2. get_rulesets_config / set_rulesets_config — чтение/запись state.json.
  3. inject_route_rulesets — инъекция route.rule_set + route.rules.
  4. Идемпотентность — повторный вызов не дублирует.
  5. Обратная совместимость — когда фича выключена, конфиг не меняется.
  6. Интеграция с subscription.build_subscription_singbox_config.
  7. Интеграция с rest_api._generate_singbox_config.
  8. Защита от опечатки hydraronique/roscomprn-geosite (которой в коде быть
     не должно — это несуществующий репозиторий, все URL возвращают 404).
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core(state_json: str | None = None):
    """Инициализирует фейковый chimera._core с state.json.

    state_json=None  → state.json не существует (чистая установка).
    state_json="..." → содержимое state.json (для тестов с предустановленным state).
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}

    # Временный файл для state.json. Каждый тест получает свежий файл.
    tmp_dir = tempfile.mkdtemp(prefix="chimera_test_")
    state_file = Path(tmp_dir) / "state.json"
    if state_json is not None:
        state_file.write_text(state_json)

    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)

    # Подменяем STATE_FILE на наш временный.
    g["STATE_FILE"] = state_file

    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return state_file


def _clear_singbox_rulesets_module():
    """Принудительно перезагружает модуль, чтобы он подхватил новый _core."""
    mods_to_remove = [k for k in list(sys.modules)
                      if k.startswith("chimera.modules.singbox_client_rulesets")]
    for m in mods_to_remove:
        del sys.modules[m]


# =============================================================================
#  1. КАТАЛОГ RULESET_CATALOG
# =============================================================================
class TestRulesetCatalog(unittest.TestCase):
    """Каталог RULESET_CATALOG — структура и правильность URL'ов."""

    def setUp(self):
        _setup_core()
        _clear_singbox_rulesets_module()

    def test_catalog_non_empty(self):
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        self.assertGreater(len(RULESET_CATALOG), 0)

    def test_each_entry_has_required_fields(self):
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        for tag, meta in RULESET_CATALOG.items():
            with self.subTest(tag=tag):
                self.assertIn("url", meta)
                self.assertIn("action", meta)
                self.assertIn("label", meta)
                self.assertIn("hint", meta)
                self.assertIn(meta["action"], ("direct", "proxy"),
                              f"action must be 'direct' or 'proxy', got: {meta['action']}")

    def test_urls_use_correct_repo_name(self):
        """ВСЕ URL'ы должны указывать на правильный репозиторий
        hydraponique/roscomvpn-geosite (НЕ hydraronique/roscomprn-geosite —
        это распространённая опечатка, такого репо не существует, 404)."""
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        for tag, meta in RULESET_CATALOG.items():
            url = meta["url"]
            with self.subTest(tag=tag, url=url):
                # ПРАВИЛЬНОЕ имя репозитория.
                self.assertIn("hydraponique/roscomvpn-geosite", url,
                              f"URL must use hydraponique/roscomvpn-geosite, got: {url}")
                # ОПЕЧАТКА — НЕ должна встречаться нигде в коде.
                self.assertNotIn("hydraronique", url,
                                 f"Found typo 'hydraronique' in URL: {url}")
                self.assertNotIn("roscomprn", url,
                                 f"Found typo 'roscomprn' in URL: {url}")

    def test_urls_use_jsdelivr_cdn(self):
        """URL'ы должны использовать cdn.jsdelivr.net — Cloudflare-backed CDN,
        хорошо доступный из РФ."""
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        for tag, meta in RULESET_CATALOG.items():
            with self.subTest(tag=tag):
                self.assertTrue(meta["url"].startswith("https://cdn.jsdelivr.net/"),
                                f"URL should use jsdelivr CDN: {meta['url']}")

    def test_urls_have_srs_extension(self):
        """Все URL'ы должны указывать на .srs (binary) файлы."""
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        for tag, meta in RULESET_CATALOG.items():
            with self.subTest(tag=tag):
                self.assertTrue(meta["url"].endswith(".srs"),
                                f"URL must end with .srs: {meta['url']}")

    def test_tags_are_unique(self):
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        tags = list(RULESET_CATALOG.keys())
        self.assertEqual(len(tags), len(set(tags)),
                         f"Tags must be unique: {tags}")

    def test_default_selected_subset_of_catalog(self):
        from chimera.modules.singbox_client_rulesets import (
            RULESET_CATALOG, DEFAULT_SELECTED,
        )
        for tag in DEFAULT_SELECTED:
            self.assertIn(tag, RULESET_CATALOG,
                          f"DEFAULT_SELECTED tag '{tag}' not in catalog")

    def test_default_selected_has_ru_direct(self):
        """Дефолтный набор ДОЛЖЕН включать ru-direct — это решает основную
        боль пользователя (Госуслуги/WB/Ozon/Детский Мир жалуются на VPN)."""
        from chimera.modules.singbox_client_rulesets import DEFAULT_SELECTED
        self.assertIn("ru-direct", DEFAULT_SELECTED)


# =============================================================================
#  2. ЧТЕНИЕ/ЗАПИСЬ STATE
# =============================================================================
class TestStateReadWrite(unittest.TestCase):
    """get_rulesets_config / set_rulesets_config — чтение/запись state.json."""

    def setUp(self):
        _setup_core()
        _clear_singbox_rulesets_module()

    def test_default_when_no_state_file(self):
        """Без state.json — возвращает defaults (enabled=False)."""
        from chimera.modules.singbox_client_rulesets import (
            get_rulesets_config, DEFAULT_SELECTED,
        )
        cfg = get_rulesets_config()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(set(cfg["selected"]), set(DEFAULT_SELECTED))

    def test_default_when_field_missing(self):
        """state.json есть, но поля singbox_client_rulesets нет → defaults."""
        _setup_core(json.dumps({"domain": "example.com", "uuid": "abc"}))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import get_rulesets_config
        cfg = get_rulesets_config()
        self.assertFalse(cfg["enabled"])

    def test_set_and_get_enabled(self):
        _setup_core(json.dumps({"domain": "example.com"}))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import (
            get_rulesets_config, set_rulesets_config,
        )
        set_rulesets_config(True, ["ru-direct", "private-direct"])
        cfg = get_rulesets_config()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(set(cfg["selected"]), {"ru-direct", "private-direct"})

    def test_set_persists_to_state_json(self):
        """set_rulesets_config должен реально писать в state.json."""
        state_file = _setup_core(json.dumps({"domain": "example.com"}))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import set_rulesets_config
        set_rulesets_config(True, ["ru-direct"])
        # Читаем файл напрямую — без использования API модуля.
        raw = json.loads(state_file.read_text())
        self.assertIn("singbox_client_rulesets", raw)
        self.assertTrue(raw["singbox_client_rulesets"]["enabled"])
        self.assertIn("ru-direct", raw["singbox_client_rulesets"]["selected"])

    def test_set_preserves_other_state_fields(self):
        """set_rulesets_config не должен затирать другие поля state.json."""
        state_file = _setup_core(json.dumps({
            "domain": "example.com",
            "uuid": "test-uuid",
            "server_port": 443,
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import set_rulesets_config
        set_rulesets_config(True, ["ru-direct"])
        raw = json.loads(state_file.read_text())
        # Все существующие поля должны остаться.
        self.assertEqual(raw["domain"], "example.com")
        self.assertEqual(raw["uuid"], "test-uuid")
        self.assertEqual(raw["server_port"], 443)
        # И новое поле добавлено.
        self.assertIn("singbox_client_rulesets", raw)

    def test_invalid_tags_filtered_out(self):
        """Несуществующие теги (которых нет в каталоге) — отфильтровываются."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct", "nonexistent-tag", "another-fake"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import get_rulesets_config
        cfg = get_rulesets_config()
        self.assertIn("ru-direct", cfg["selected"])
        self.assertNotIn("nonexistent-tag", cfg["selected"])
        self.assertNotIn("another-fake", cfg["selected"])

    def test_empty_selected_falls_back_to_default(self):
        """Если selected=[] — возвращаем DEFAULT_SELECTED."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": [],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import (
            get_rulesets_config, DEFAULT_SELECTED,
        )
        cfg = get_rulesets_config()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(set(cfg["selected"]), set(DEFAULT_SELECTED))


# =============================================================================
#  3. ИНЪЕКЦИЯ В SING-BOX КОНФИГ
# =============================================================================
class TestInjectRouteRulesets(unittest.TestCase):
    """inject_route_rulesets — добавление route.rule_set + route.rules."""

    def setUp(self):
        _setup_core()
        _clear_singbox_rulesets_module()

    def _minimal_config(self) -> dict:
        return {
            "outbounds": [
                {"type": "vless", "tag": "vless-out"},
                {"type": "direct", "tag": "direct"},
            ],
        }

    def test_no_injection_when_disabled(self):
        """Когда фича выключена — конфиг возвращается без изменений."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {"enabled": False, "selected": ["ru-direct"]},
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        result = inject_route_rulesets(cfg, "vless-out")
        # Должен вернуться тот же dict без ключа "route".
        self.assertNotIn("route", result)

    def test_no_injection_when_field_missing(self):
        """Когда поля singbox_client_rulesets нет в state — конфиг без изменений."""
        _setup_core(json.dumps({"domain": "example.com"}))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        result = inject_route_rulesets(cfg, "vless-out")
        self.assertNotIn("route", result)

    def test_injection_adds_route_when_enabled(self):
        """Когда фича включена — добавляется route.rule_set + route.rules."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct", "geoblock-ru-proxy"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        result = inject_route_rulesets(cfg, "vless-out")
        self.assertIn("route", result)
        self.assertIn("rule_set", result["route"])
        self.assertIn("rules", result["route"])
        self.assertIn("final", result["route"])
        self.assertEqual(result["route"]["final"], "vless-out")

    def test_rule_set_has_correct_format(self):
        """Каждый rule_set entry должен иметь правильную структуру."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        result = inject_route_rulesets(cfg, "vless-out")
        for rs in result["route"]["rule_set"]:
            self.assertEqual(rs["type"], "remote")
            self.assertIn("tag", rs)
            self.assertEqual(rs["format"], "binary")
            self.assertIn("url", rs)
            self.assertIn("download_detour", rs)
            self.assertEqual(rs["download_detour"], "vless-out")

    def test_rules_grouped_by_action(self):
        """Rules должны быть сгруппированы: один rule для direct, один для proxy."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct", "private-direct", "geoblock-ru-proxy"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        result = inject_route_rulesets(cfg, "vless-out")
        rules = result["route"]["rules"]
        # Должно быть 2 правила: direct (с 2 тегами) + proxy (с 1 тегом).
        direct_rules = [r for r in rules if r.get("outbound") == "direct"]
        proxy_rules = [r for r in rules if r.get("outbound") == "vless-out"]
        self.assertEqual(len(direct_rules), 1)
        self.assertEqual(len(proxy_rules), 1)
        self.assertEqual(len(direct_rules[0]["rule_set"]), 2)
        self.assertEqual(len(proxy_rules[0]["rule_set"]), 1)

    def test_idempotent(self):
        """Повторный вызов не должен дублировать rule_set и rules."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct", "geoblock-ru-proxy"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        inject_route_rulesets(cfg, "vless-out")
        # Запоминаем количество rule_set и rules.
        first_rs_count = len(cfg["route"]["rule_set"])
        first_rules_count = len(cfg["route"]["rules"])
        # Второй вызов — не должен ничего добавить.
        inject_route_rulesets(cfg, "vless-out")
        self.assertEqual(len(cfg["route"]["rule_set"]), first_rs_count)
        self.assertEqual(len(cfg["route"]["rules"]), first_rules_count)

    def test_preserves_existing_route_final(self):
        """Если route.final уже есть — не перезаписываем."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        cfg["route"] = {"final": "custom-tag"}
        result = inject_route_rulesets(cfg, "vless-out")
        self.assertEqual(result["route"]["final"], "custom-tag")

    def test_preserves_existing_rules(self):
        """Существующие route.rules не затираются — добавляем наши в начало."""
        _setup_core(json.dumps({
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct"],
            }
        }))
        _clear_singbox_rulesets_module()
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        cfg = self._minimal_config()
        existing_rule = {"domain": ["example.com"], "outbound": "block"}
        cfg["route"] = {"rules": [existing_rule]}
        result = inject_route_rulesets(cfg, "vless-out")
        rules = result["route"]["rules"]
        # Существующее правило должно остаться.
        self.assertIn(existing_rule, rules)
        # И наше новое — тоже добавлено.
        direct_rules = [r for r in rules if r.get("outbound") == "direct"]
        self.assertEqual(len(direct_rules), 1)


# =============================================================================
#  4. ИНТЕГРАЦИЯ С subscription.build_subscription_singbox_config
# =============================================================================
class TestSubscriptionIntegration(unittest.TestCase):
    """Интеграция: subscription.build_subscription_singbox_config уважает фичу."""

    def setUp(self):
        _setup_core()
        _clear_singbox_rulesets_module()

    def test_subscription_no_rulesets_when_disabled(self):
        """Когда фича выключена — sing-box подписка остаётся как раньше."""
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test"})
        config = json.loads(result)
        # Только outbounds + route.final, без rule_set.
        self.assertIn("outbounds", config)
        self.assertIn("route", config)
        self.assertIn("final", config["route"])
        self.assertNotIn("rule_set", config.get("route", {}))

    def test_subscription_includes_rulesets_when_enabled(self):
        """Когда фича включена — sing-box подписка содержит route.rule_set."""
        _setup_core(json.dumps({
            "domain": "example.com",
            "uuid": "test-uuid",
            "public_key": "test-pbk",
            "short_id": "abc",
            "protocol_mode": "reality",
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct", "geoblock-ru-proxy"],
            }
        }))
        _clear_singbox_rulesets_module()
        # Перезагружаем subscription, чтобы он подхватил новый _core.
        for m in list(sys.modules):
            if m.startswith("chimera.modules.subscription"):
                del sys.modules[m]
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test"})
        config = json.loads(result)
        self.assertIn("route", config)
        self.assertIn("rule_set", config["route"])
        self.assertIn("rules", config["route"])
        rule_set_tags = {rs["tag"] for rs in config["route"]["rule_set"]}
        self.assertIn("ru-direct", rule_set_tags)
        self.assertIn("geoblock-ru-proxy", rule_set_tags)


# =============================================================================
#  5. ИНТЕГРАЦИЯ С rest_api._generate_singbox_config
# =============================================================================
class TestRestApiIntegration(unittest.TestCase):
    """Интеграция: rest_api._generate_singbox_config уважает фичу."""

    def setUp(self):
        _setup_core()
        _clear_singbox_rulesets_module()

    def test_rest_api_no_rulesets_when_disabled(self):
        """Когда фича выключена — /api/portal/singbox возвращает только outbounds."""
        from chimera.modules import rest_api
        result = rest_api._generate_singbox_config({"uuid": "test"})
        config = json.loads(result)
        self.assertIn("outbounds", config)
        # Должно НЕ быть route (исходное поведение — только outbounds).
        self.assertNotIn("route", config)

    def test_rest_api_includes_rulesets_when_enabled(self):
        """Когда фича включена — /api/portal/singbox содержит route.rule_set."""
        _setup_core(json.dumps({
            "domain": "example.com",
            "uuid": "test-uuid",
            "public_key": "test-pbk",
            "short_id": "abc",
            "protocol_mode": "reality",
            "singbox_client_rulesets": {
                "enabled": True,
                "selected": ["ru-direct"],
            }
        }))
        _clear_singbox_rulesets_module()
        for m in list(sys.modules):
            if m.startswith("chimera.modules.rest_api"):
                del sys.modules[m]
        from chimera.modules import rest_api
        result = rest_api._generate_singbox_config({"uuid": "test"})
        config = json.loads(result)
        self.assertIn("route", config)
        self.assertIn("rule_set", config["route"])
        self.assertIn("final", config["route"])


# =============================================================================
#  6. ЗАЩИТА ОТ ОПЕЧАТКИ В ИМЕНИ РЕПОЗИТОРИЯ
# =============================================================================
class TestNoTypoInCodebase(unittest.TestCase):
    """Защита от регрессии: опечатка hydraronique/roscomprn-geosite не должна
    попасть в URL'ы (она ведёт к 404 на всех URL'ах).

    Проверяем именно URL'ы в RULESET_CATALOG (а не исходник целиком), т.к.
    в комментарии-документации модуля слово «hydraronique» упоминается как
    ПРИМЕР опечатки — это образовательная цель, не баг.
    """

    def setUp(self):
        _setup_core()
        _clear_singbox_rulesets_module()

    def test_correct_repo_name_in_all_urls(self):
        from chimera.modules.singbox_client_rulesets import RULESET_CATALOG
        for tag, meta in RULESET_CATALOG.items():
            url = meta["url"]
            with self.subTest(tag=tag):
                self.assertIn("hydraponique/roscomvpn-geosite", url)
                self.assertNotIn("hydraronique", url)
                self.assertNotIn("roscomprn-geosite", url)

    def test_no_typo_in_default_selected(self):
        """DEFAULT_SELECTED — только валидные теги из каталога."""
        from chimera.modules.singbox_client_rulesets import (
            DEFAULT_SELECTED, RULESET_CATALOG,
        )
        for tag in DEFAULT_SELECTED:
            self.assertIn(tag, RULESET_CATALOG)
            # Дополнительно — URL этого тега не содержит опечатку.
            self.assertNotIn("hydraronique", RULESET_CATALOG[tag]["url"])


if __name__ == "__main__":
    unittest.main()
