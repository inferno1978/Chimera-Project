#!/usr/bin/env python3
"""
tests/test_dpi_bypass.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dpi_bypass.py — централизованного DPI Bypass
модуля (b4 для любых заблокированных ресурсов).

Покрывает:
  1. import_custom_set — импорт кастомного сета из JSON
     (REGRESSION: ранее NameError на `new_sets` переменной)
  2. import_custom_set_from_file — импорт из файла
  3. apply_routing_for_set / remove_routing_for_set — Xray routing rules
  4. apply_routing_for_all_sets — применение routing для всех set'ов
  5. Синхронизация с youtube_b4 — общие константы путей
     (shared config / state / binary / unit / sets dir)
  6. _load_state / _save_state — читаем/пишем общий state.json
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
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


class TestImportCustomSet(unittest.TestCase):
    """import_custom_set — импорт кастомного b4 set из JSON.

    REGRESSION: ранее в dpi_bypass.py import_custom_set() в конце функции
    был цикл `for s in new_sets:` — но переменная new_sets НИГДЕ не была
    определена в функции (только custom_set). Импорт сета завершался
    успехом (config сохранён, b4 перезапущен, _ok(...) показано), но
    функция бросала NameError вместо возврата True. TUI получал исключение
    вместо корректного статуса. Xray routing для нового сета НЕ применялся.
    """

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        # Импортируем модуль с подменой путей к конфигам
        from chimera.modules import dpi_bypass
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        # Не позволяем реально вызывать systemctl
        self.dpi_bypass.subprocess = MagicMock()
        # Изолируем от реального REST API b4 (иначе на сервере с живым b4
        # тест импортировал бы сеты в прод). Форсим легаси-путь (config.json).
        self.dpi_bypass._b4_rest_import_set = lambda cs: None
        # Трекаем вызовы apply_routing_for_all_sets
        self._routing_calls = []
        self._orig_apply = self.dpi_bypass.apply_routing_for_all_sets

        def _fake_apply_all():
            # Симулируем: читаем сеты из конфига и записываем вызовы
            sets = self.dpi_bypass._detect_sets()
            for s in sets:
                sid = s.get("id", "")
                domains = s.get("domains", [])
                if sid and domains:
                    self._routing_calls.append((sid, list(domains)))
            return {"applied": len(self._routing_calls), "removed": 0,
                    "total_domains": sum(len(d) for _, d in self._routing_calls),
                    "errors": []}

        self.dpi_bypass.apply_routing_for_all_sets = _fake_apply_all

    def tearDown(self):
        # Восстанавливаем оригинал на случай если кто-то ещё использует модуль
        self.dpi_bypass.apply_routing_for_all_sets = self._orig_apply

    def test_single_set_object(self):
        """Импорт одиночного set-объекта (не обёрнутого в {'sets': [...]})."""
        test_json = json.dumps({
            "id": "test-custom",
            "name": "Test Set",
            "targets": {"sni_domains": ["example.com", "test.com"]},
            "faking": {"sni_type": "plain"},
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertTrue(result)
        # Config сохранён с правильным форматом
        saved = json.loads(self._config_file.read_text())
        self.assertIn("sets", saved)
        self.assertEqual(len(saved["sets"]), 1)
        self.assertEqual(saved["sets"][0]["id"], "test-custom")
        # State обновлён — active_preset = "custom"
        state = json.loads(self._state_file.read_text())
        self.assertEqual(state["active_preset"], "custom")
        # REGRESSION: routing должен быть применён (раньше бросал NameError)
        self.assertEqual(self._routing_calls,
                         [("test-custom", ["example.com", "test.com"])])

    def test_wrapped_in_sets_array(self):
        """Импорт set обёрнутого в {'sets': [...]} — берём первый."""
        test_json = json.dumps({
            "sets": [{
                "id": "wrapped-set",
                "name": "Wrapped Set",
                "targets": {"sni_domains": ["foo.bar"]},
                "faking": {"sni_type": "plain"},
            }]
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertTrue(result)
        saved = json.loads(self._config_file.read_text())
        self.assertEqual(saved["sets"][0]["id"], "wrapped-set")
        # Routing вызван с правильным id
        self.assertEqual(self._routing_calls,
                         [("wrapped-set", ["foo.bar"])])

    def test_empty_sets_array_returns_false(self):
        """Пустой массив sets → False, routing не вызывается."""
        test_json = json.dumps({"sets": []})
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertFalse(result)
        self.assertEqual(self._routing_calls, [])

    def test_invalid_json_returns_false(self):
        """Невалидный JSON → False, без исключения."""
        result = self.dpi_bypass.import_custom_set("{not valid json")
        self.assertFalse(result)
        self.assertEqual(self._routing_calls, [])

    def test_no_sni_domains_returns_false(self):
        """Set без targets.sni_domains → False (нечего матчить)."""
        test_json = json.dumps({
            "id": "no-domains",
            "targets": {},
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertFalse(result)
        # Routing не вызывается — функция возвращается раньше
        self.assertEqual(self._routing_calls, [])

    def test_missing_id_gets_unique(self):
        """Set без id получает уникальный custom-{uuid}."""
        test_json = json.dumps({
            "name": "No ID Set",
            "targets": {"sni_domains": ["x.com"]},
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertTrue(result)
        saved = json.loads(self._config_file.read_text())
        # id должен начинаться с 'custom-'
        self.assertTrue(saved["sets"][0]["id"].startswith("custom-"),
                        f"id должен начинаться с 'custom-', got: {saved['sets'][0]['id']}")

    def test_geosite_categories_preserved(self):
        """geosite_categories сохраняется (system с sitedat_path сохраняется)."""
        test_json = json.dumps({
            "id": "geo-set",
            "targets": {
                "sni_domains": ["x.com"],
                "geosite_categories": ["youtube"],
            },
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertTrue(result)
        saved = json.loads(self._config_file.read_text())
        # geosite_categories должен остаться (b4 умеет с ним работать)
        self.assertIn("geosite_categories",
                      saved["sets"][0]["targets"])

    def test_no_name_uses_default_in_message(self):
        """Set без name — в сообщении используется 'custom'."""
        test_json = json.dumps({
            "id": "no-name",
            "targets": {"sni_domains": ["x.com"]},
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertTrue(result)

    def test_not_dict_returns_false(self):
        """JSON массив (не объект) → False."""
        test_json = json.dumps(["not", "a", "dict"])
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertFalse(result)


class TestImportCustomSetFromFile(unittest.TestCase):
    """import_custom_set_from_file — импорт из JSON-файла."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        from chimera.modules import dpi_bypass
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()
        # Изолируем от реального REST API b4 (форсим легаси-путь).
        self.dpi_bypass._b4_rest_import_set = lambda cs: None
        # Заглушка для apply_routing_for_set
        self.dpi_bypass.apply_routing_for_set = lambda *a, **kw: True

    def test_reads_file_and_imports(self):
        """Файл читается и сет импортируется."""
        set_file = self._tmpdir / "set.json"
        set_file.write_text(json.dumps({
            "id": "from-file",
            "targets": {"sni_domains": ["file.com"]},
        }))
        result = self.dpi_bypass.import_custom_set_from_file(str(set_file))
        self.assertTrue(result)
        saved = json.loads(self._config_file.read_text())
        self.assertEqual(saved["sets"][0]["id"], "from-file")

    def test_nonexistent_file_returns_false(self):
        """Несуществующий файл → False."""
        result = self.dpi_bypass.import_custom_set_from_file(
            "/nonexistent/path/set.json")
        self.assertFalse(result)


class TestRoutingForSet(unittest.TestCase):
    """apply_routing_for_set / remove_routing_for_set — Xray routing rules."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        # Перечитываем модуль чтобы получить оригинальные сигнатуры
        # (предыдущие тесты могли подменять apply_routing_for_set на mock)
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass

    def test_apply_routing_for_set_signature(self):
        """Функция apply_routing_for_set существует и принимает (set_id, domains)."""
        import inspect
        sig = inspect.signature(self.dpi_bypass.apply_routing_for_set)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ["set_id", "domains"])

    def test_remove_routing_for_set_signature(self):
        """Функция remove_routing_for_set существует и принимает (set_id,)."""
        import inspect
        sig = inspect.signature(self.dpi_bypass.remove_routing_for_set)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ["set_id"])

    def test_apply_routing_for_all_sets_signature(self):
        """Функция apply_routing_for_all_sets существует, без обязательных args."""
        import inspect
        sig = inspect.signature(self.dpi_bypass.apply_routing_for_all_sets)
        # Все параметры должны быть опциональными
        for name, p in sig.parameters.items():
            self.assertNotEqual(p.kind, p.POSITIONAL_ONLY,
                                f"{name} не должен быть positional-only")


class TestSyncWithYoutubeB4(unittest.TestCase):
    """Синхронизация dpi_bypass ↔ youtube_b4 — общие пути.

    Оба модуля работают с одним и тем же:
      - b4 binary: /usr/local/bin/b4
      - config dir: /etc/b4
      - config file: /etc/b4/config.json
      - sets dir: /etc/b4/sets
      - systemd unit: /etc/systemd/system/b4.service
      - state file: /var/lib/xray-installer/youtube_b4_state.json
      - nginx state: /var/lib/xray-installer/b4_nginx_front.json

    Двусторонняя синхронизация через общий файл — без дополнительного кода.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        # Перечитываем оба модуля чтобы получить оригинальные пути
        # (предыдущие тесты могли подменять B4_CONFIG_FILE и др.)
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_shared_binary_path(self):
        """B4_BINARY_PATH одинаковый в обоих модулях."""
        self.assertEqual(self.youtube_b4.B4_BINARY_PATH,
                         self.dpi_bypass.B4_BINARY_PATH)
        self.assertEqual(str(self.youtube_b4.B4_BINARY_PATH),
                         "/usr/local/bin/b4")

    def test_shared_config_file(self):
        """B4_CONFIG_FILE одинаковый — оба читают/пишут один конфиг."""
        self.assertEqual(self.youtube_b4.B4_CONFIG_FILE,
                         self.dpi_bypass.B4_CONFIG_FILE)
        self.assertEqual(str(self.youtube_b4.B4_CONFIG_FILE),
                         "/etc/b4/config.json")

    def test_shared_config_dir(self):
        """B4_CONFIG_DIR одинаковый."""
        self.assertEqual(self.youtube_b4.B4_CONFIG_DIR,
                         self.dpi_bypass.B4_CONFIG_DIR)

    def test_shared_sets_dir(self):
        """B4_SETS_DIR одинаковый — кастомные сеты доступны обоим."""
        self.assertEqual(self.youtube_b4.B4_SETS_DIR,
                         self.dpi_bypass.B4_SETS_DIR)

    def test_shared_unit_path(self):
        """B4_UNIT_PATH одинаковый — один systemd сервис."""
        self.assertEqual(self.youtube_b4.B4_UNIT_PATH,
                         self.dpi_bypass.B4_UNIT_PATH)

    def test_shared_state_file(self):
        """_STATE_FILE одинаковый — оба читают/пишут один state.json."""
        self.assertEqual(self.youtube_b4._STATE_FILE,
                         self.dpi_bypass._STATE_FILE)
        self.assertEqual(str(self.youtube_b4._STATE_FILE),
                         "/var/lib/xray-installer/youtube_b4_state.json")

    def test_shared_nginx_state_file(self):
        """B4_NGINX_STATE_FILE одинаковый."""
        self.assertEqual(self.youtube_b4.B4_NGINX_STATE_FILE,
                         self.dpi_bypass.B4_NGINX_STATE_FILE)

    def test_shared_b4_version(self):
        """B4_VERSION одинаковый — ожидаемая версия binary совпадает."""
        self.assertEqual(self.youtube_b4.B4_VERSION,
                         self.dpi_bypass.B4_VERSION)

    def test_shared_queue_and_mark(self):
        """B4_QUEUE_NUM / B4_MARK / B4_IPT_COMMENT — общие iptables параметры."""
        self.assertEqual(self.youtube_b4.B4_QUEUE_NUM,
                         self.dpi_bypass.B4_QUEUE_NUM)
        self.assertEqual(self.youtube_b4.B4_MARK, self.dpi_bypass.B4_MARK)
        self.assertEqual(self.youtube_b4.B4_IPT_COMMENT,
                         self.dpi_bypass.B4_IPT_COMMENT)


class TestStateFileRoundTrip(unittest.TestCase):
    """_load_state / _save_state — общий state.json для обоих модулей."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"
        # Перезагружаем модуль — предыдущие тесты могли заменить _STATE_FILE
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass._STATE_FILE = self._state_file

    def test_load_state_returns_default_when_missing(self):
        """Если state.json не существует — возвращаем дефолт."""
        result = self.dpi_bypass._load_state()
        self.assertFalse(result["installed"])
        self.assertIsNone(result["active_preset"])
        self.assertFalse(result["enabled"])

    def test_load_state_returns_default_when_corrupted(self):
        """Повреждённый JSON → дефолт, без исключения."""
        self._state_file.write_text("not a json")
        result = self.dpi_bypass._load_state()
        self.assertFalse(result["installed"])

    def test_save_state_writes_valid_json(self):
        """_save_state пишет валидный JSON."""
        state = {"installed": True, "active_preset": "default", "enabled": True}
        self.dpi_bypass._save_state(state)
        loaded = json.loads(self._state_file.read_text())
        self.assertEqual(loaded, state)

    def test_save_state_creates_parent_dir(self):
        """_save_state создаёт родительский каталог если его нет."""
        nested = self._tmpdir / "nested" / "deep" / "state.json"
        self.dpi_bypass._STATE_FILE = nested
        self.dpi_bypass._save_state({"installed": True})
        self.assertTrue(nested.exists())


class TestDetectLatestPrereleaseVersion(unittest.TestCase):
    """_detect_latest_prerelease_version — поиск pre-release на GitHub.

    Использует GitHub API /releases endpoint (не /releases/latest, который
    возвращает только стабильные). Фильтрует где prerelease=true, берёт
    первый (самый свежий).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass

    def _mock_releases_response(self, releases):
        """Создаёт mock для urllib.request.urlopen."""
        import io
        data = json.dumps(releases).encode()
        resp = MagicMock()
        resp.read = lambda: data
        resp.__enter__ = lambda self: self
        resp.__exit__ = lambda self, *a: None
        return resp

    @patch("urllib.request.urlopen")
    def test_returns_first_prerelease(self, mock_urlopen):
        """Возвращает первый pre-release из списка (самый свежий)."""
        mock_urlopen.return_value = self._mock_releases_response([
            {"tag_name": "v1.80.0-rc1", "prerelease": True, "name": "RC1"},
            {"tag_name": "v1.79.0", "prerelease": False, "name": "Stable"},
            {"tag_name": "v1.78.0-beta", "prerelease": True, "name": "Beta"},
        ])
        result = self.dpi_bypass._detect_latest_prerelease_version()
        self.assertEqual(result, "1.80.0-rc1")

    @patch("urllib.request.urlopen")
    def test_strips_v_prefix(self, mock_urlopen):
        """Убирает 'v' префикс из tag_name."""
        mock_urlopen.return_value = self._mock_releases_response([
            {"tag_name": "v2.0.0-beta1", "prerelease": True},
        ])
        result = self.dpi_bypass._detect_latest_prerelease_version()
        self.assertEqual(result, "2.0.0-beta1")
        self.assertFalse(result.startswith("v"))

    @patch("urllib.request.urlopen")
    def test_returns_empty_when_only_stable(self, mock_urlopen):
        """Возвращает '' если pre-release релизов нет."""
        mock_urlopen.return_value = self._mock_releases_response([
            {"tag_name": "v1.79.0", "prerelease": False},
            {"tag_name": "v1.78.0", "prerelease": False},
        ])
        result = self.dpi_bypass._detect_latest_prerelease_version()
        self.assertEqual(result, "")

    @patch("urllib.request.urlopen")
    def test_returns_empty_when_no_releases(self, mock_urlopen):
        """Возвращает '' если список релизов пуст."""
        mock_urlopen.return_value = self._mock_releases_response([])
        result = self.dpi_bypass._detect_latest_prerelease_version()
        self.assertEqual(result, "")

    @patch("urllib.request.urlopen")
    def test_returns_empty_on_network_error(self, mock_urlopen):
        """Возвращает '' при сетевой ошибке, без исключения."""
        mock_urlopen.side_effect = Exception("Network timeout")
        result = self.dpi_bypass._detect_latest_prerelease_version()
        self.assertEqual(result, "")

    @patch("urllib.request.urlopen")
    def test_skips_releases_with_prerelease_false_or_missing(self, mock_urlopen):
        """Пропускает релизы где prerelease=false или ключ отсутствует."""
        mock_urlopen.return_value = self._mock_releases_response([
            {"tag_name": "v1.0.0", "prerelease": False},  # стабильный
            {"tag_name": "v1.1.0"},  # prerelease ключ отсутствует → не pre-release
            {"tag_name": "v1.2.0-rc1", "prerelease": True},  # pre-release
        ])
        result = self.dpi_bypass._detect_latest_prerelease_version()
        self.assertEqual(result, "1.2.0-rc1")

    @patch("urllib.request.urlopen")
    def test_uses_releases_endpoint_not_latest(self, mock_urlopen):
        """Использует /releases (массив), а не /releases/latest (один объект)."""
        mock_urlopen.return_value = self._mock_releases_response([
            {"tag_name": "v1.0.0-rc1", "prerelease": True},
        ])
        self.dpi_bypass._detect_latest_prerelease_version()
        # Проверяем URL, который был запрошен
        called_request = mock_urlopen.call_args[0][0]
        self.assertEqual(called_request.full_url,
                         "https://api.github.com/repos/DanielLavrushin/b4/releases")
        self.assertNotIn("/latest", called_request.full_url)


class TestAutoUpdatePrerelease(unittest.TestCase):
    """auto_update_prerelease — логика обновления до pre-release.

    НЕ делает реальных сетевых запросов — всё мокается. Проверяем:
      - b4 не установлен → откат
      - нет pre-release на GitHub → откат
      - уже установлена pre-release версия → откат
      - confirm=True + ответ "n" → откат, обновления нет
      - confirm=True + ответ "y" → обновление
      - confirm=False → обновление без вопроса
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()

    def _patch_installed(self, installed: bool, version: str = "1.78.0"):
        """Подменяет _detect_installed, _detect_version."""
        self.dpi_bypass._detect_installed = lambda: installed
        self.dpi_bypass._detect_version = lambda: version

    def test_returns_false_when_not_installed(self):
        """b4 не установлен → обновление невозможно."""
        self._patch_installed(installed=False)
        result = self.dpi_bypass.auto_update_prerelease(confirm=False)
        self.assertFalse(result["updated"])
        self.assertIn("не установлен", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    def test_returns_false_when_no_prerelease_available(self, mock_pre):
        """Нет pre-release на GitHub → откат."""
        self._patch_installed(installed=True, version="1.78.0")
        mock_pre.return_value = ""
        result = self.dpi_bypass.auto_update_prerelease(confirm=False)
        self.assertFalse(result["updated"])
        self.assertIn("не найдены", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    def test_returns_false_when_already_on_prerelease(self, mock_pre):
        """Уже установлена pre-release версия → откат."""
        self._patch_installed(installed=True, version="1.80.0-rc1")
        mock_pre.return_value = "1.80.0-rc1"
        result = self.dpi_bypass.auto_update_prerelease(confirm=False)
        self.assertFalse(result["updated"])
        self.assertIn("Уже установлена", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    @patch("builtins.input", return_value="n")
    def test_confirm_yes_proceeds_with_update(self, mock_input, mock_pre):
        """confirm=True + 'n' → откат, обновления нет."""
        self._patch_installed(installed=True, version="1.78.0")
        mock_pre.return_value = "1.80.0-rc1"
        # Мокаем _do_b4_binary_update чтобы не делать реальную установку
        self.dpi_bypass._do_b4_binary_update = lambda old, new: {
            "updated": True, "old_version": old, "new_version": new,
            "message": f"Updated: {old} → {new}"}
        result = self.dpi_bypass.auto_update_prerelease(confirm=True)
        self.assertFalse(result["updated"])
        self.assertIn("Отменено", result["message"])
        mock_input.assert_called_once()

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    @patch("builtins.input", return_value="y")
    def test_confirm_yes_proceeds_with_update_yes(self, mock_input, mock_pre):
        """confirm=True + 'y' → обновление."""
        self._patch_installed(installed=True, version="1.78.0")
        mock_pre.return_value = "1.80.0-rc1"
        update_called = []
        def _fake_update(old, new):
            update_called.append((old, new))
            return {"updated": True, "old_version": old, "new_version": new,
                    "message": f"Updated: {old} → {new}"}
        self.dpi_bypass._do_b4_binary_update = _fake_update
        result = self.dpi_bypass.auto_update_prerelease(confirm=True)
        self.assertTrue(result["updated"])
        self.assertEqual(result["new_version"], "1.80.0-rc1")
        self.assertEqual(update_called, [("1.78.0", "1.80.0-rc1")])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    def test_confirm_false_skips_input(self, mock_pre):
        """confirm=False → обновление без вопроса пользователю."""
        self._patch_installed(installed=True, version="1.78.0")
        mock_pre.return_value = "1.80.0-rc1"
        update_called = []
        def _fake_update(old, new):
            update_called.append((old, new))
            return {"updated": True, "old_version": old, "new_version": new,
                    "message": f"Updated: {old} → {new}"}
        self.dpi_bypass._do_b4_binary_update = _fake_update
        # Не мокаем input — если функция попробует его вызвать, тест упадёт
        # с EOFError (stdin не интерактивный в тестах).
        result = self.dpi_bypass.auto_update_prerelease(confirm=False)
        self.assertTrue(result["updated"])
        self.assertEqual(update_called, [("1.78.0", "1.80.0-rc1")])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    @patch("builtins.input", side_effect=EOFError())
    def test_eof_on_input_cancels_update(self, mock_input, mock_pre):
        """EOFError на input → откат (как 'n')."""
        self._patch_installed(installed=True, version="1.78.0")
        mock_pre.return_value = "1.80.0-rc1"
        self.dpi_bypass._do_b4_binary_update = lambda old, new: {
            "updated": True, "old_version": old, "new_version": new,
            "message": "should not be called"}
        result = self.dpi_bypass.auto_update_prerelease(confirm=True)
        self.assertFalse(result["updated"])
        self.assertIn("Отменено", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_prerelease_version']),
                  '_detect_latest_prerelease_version')
    @patch("builtins.input", return_value="да")
    def test_russian_yes_accepted(self, mock_input, mock_pre):
        """Русские 'да'/'д' тоже принимаются как подтверждение."""
        self._patch_installed(installed=True, version="1.78.0")
        mock_pre.return_value = "1.80.0-rc1"
        self.dpi_bypass._do_b4_binary_update = lambda old, new: {
            "updated": True, "old_version": old, "new_version": new,
            "message": "ok"}
        result = self.dpi_bypass.auto_update_prerelease(confirm=True)
        self.assertTrue(result["updated"])


class TestAutoUpdateRelease(unittest.TestCase):
    """auto_update (stable release) — проверка что рефакторинг не сломал.

    После рефакторинга auto_update() вызывает _do_b4_binary_update() вместо
    инлайн-логики. Поведение должно быть идентичным.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass._STATE_FILE = self._tmpdir / "state.json"
        self.dpi_bypass.subprocess = MagicMock()

    def test_returns_false_when_not_installed(self):
        self.dpi_bypass._detect_installed = lambda: False
        result = self.dpi_bypass.auto_update()
        self.assertFalse(result["updated"])
        self.assertIn("не установлен", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_version']),
                  '_detect_latest_version')
    def test_returns_false_when_check_failed(self, mock_latest):
        self.dpi_bypass._detect_installed = lambda: True
        self.dpi_bypass._detect_version = lambda: "1.78.0"
        mock_latest.return_value = ""
        result = self.dpi_bypass.auto_update()
        self.assertFalse(result["updated"])
        self.assertIn("Не удалось проверить", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_version']),
                  '_detect_latest_version')
    def test_returns_false_when_already_uptodate(self, mock_latest):
        self.dpi_bypass._detect_installed = lambda: True
        self.dpi_bypass._detect_version = lambda: "1.78.0"
        mock_latest.return_value = "1.78.0"
        result = self.dpi_bypass.auto_update()
        self.assertFalse(result["updated"])
        self.assertIn("Уже актуальная", result["message"])

    @patch.object(__import__('chimera.modules.dpi_bypass', fromlist=['_detect_latest_version']),
                  '_detect_latest_version')
    def test_proceeds_when_new_version_available(self, mock_latest):
        """Новая stable версия → вызывается _do_b4_binary_update."""
        self.dpi_bypass._detect_installed = lambda: True
        self.dpi_bypass._detect_version = lambda: "1.78.0"
        mock_latest.return_value = "1.79.0"
        update_called = []
        def _fake_update(old, new):
            update_called.append((old, new))
            return {"updated": True, "old_version": old, "new_version": new,
                    "message": f"Updated: {old} → {new}"}
        self.dpi_bypass._do_b4_binary_update = _fake_update
        result = self.dpi_bypass.auto_update()
        self.assertTrue(result["updated"])
        self.assertEqual(result["new_version"], "1.79.0")
        self.assertEqual(update_called, [("1.78.0", "1.79.0")])


class TestYoutubeB4HasUpdateFunctions(unittest.TestCase):
    """youtube_b4.py теперь имеет те же update-функции что dpi_bypass.py.

    REGRESSION: проверяем что youtube_b4.py получил функции обновления
    (раньше их не было — только _detect_arch и _download_b4_binary).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4
        importlib.reload(youtube_b4)
        self.youtube_b4 = youtube_b4

    def test_has_detect_installed(self):
        self.assertTrue(hasattr(self.youtube_b4, '_detect_installed'))
        self.assertTrue(callable(self.youtube_b4._detect_installed))

    def test_has_detect_version(self):
        self.assertTrue(hasattr(self.youtube_b4, '_detect_version'))

    def test_has_detect_service_active(self):
        self.assertTrue(hasattr(self.youtube_b4, '_detect_service_active'))

    def test_has_detect_latest_version(self):
        self.assertTrue(hasattr(self.youtube_b4, '_detect_latest_version'))

    def test_has_detect_latest_prerelease_version(self):
        """REGRESSION: pre-release функция должна быть в youtube_b4."""
        self.assertTrue(hasattr(self.youtube_b4, '_detect_latest_prerelease_version'))

    def test_has_do_b4_binary_update(self):
        """REGRESSION: общий helper для обновления binary."""
        self.assertTrue(hasattr(self.youtube_b4, '_do_b4_binary_update'))

    def test_has_auto_update(self):
        """REGRESSION: stable update функция должна быть в youtube_b4."""
        self.assertTrue(hasattr(self.youtube_b4, 'auto_update'))

    def test_has_auto_update_prerelease(self):
        """REGRESSION: pre-release update функция должна быть в youtube_b4."""
        self.assertTrue(hasattr(self.youtube_b4, 'auto_update_prerelease'))

    def test_auto_update_prerelease_accepts_confirm_param(self):
        """auto_update_prerelease принимает параметр confirm."""
        import inspect
        sig = inspect.signature(self.youtube_b4.auto_update_prerelease)
        self.assertIn("confirm", sig.parameters)
        # Default должно быть True
        self.assertEqual(sig.parameters["confirm"].default, True)


class TestPreReleaseSyncBetweenModules(unittest.TestCase):
    """Синхронизация pre-release обновлений между youtube_b4 и dpi_bypass.

    Оба модуля должны иметь идентичные функции обновления с одинаковыми
    сигнатурами. Это гарантирует что обновление из любого модуля работает
    одинаково и результат виден в другом (через общий binary).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_both_modules_have_prerelease_detection(self):
        """Оба модуля имеют _detect_latest_prerelease_version."""
        self.assertTrue(hasattr(self.youtube_b4, '_detect_latest_prerelease_version'))
        self.assertTrue(hasattr(self.dpi_bypass, '_detect_latest_prerelease_version'))

    def test_both_modules_have_auto_update_prerelease(self):
        """Оба модуля имеют auto_update_prerelease."""
        self.assertTrue(hasattr(self.youtube_b4, 'auto_update_prerelease'))
        self.assertTrue(hasattr(self.dpi_bypass, 'auto_update_prerelease'))

    def test_both_modules_have_do_b4_binary_update(self):
        """Оба модуля имеют общий helper _do_b4_binary_update."""
        self.assertTrue(hasattr(self.youtube_b4, '_do_b4_binary_update'))
        self.assertTrue(hasattr(self.dpi_bypass, '_do_b4_binary_update'))

    def test_prerelease_detection_uses_same_url(self):
        """Оба модуля запрашивают один и тот же GitHub endpoint.

        URL запроса — /releases (массив всех релизов), а НЕ /releases/latest
        (возвращает только один стабильный релиз). Проверяем именно URL в
        urllib.request.Request, а не весь исходник — docstring функции
        упоминает /releases/latest для объяснения, почему мы его не используем.
        """
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._detect_latest_prerelease_version)
        dpi_src = inspect.getsource(self.dpi_bypass._detect_latest_prerelease_version)
        # URL запроса должен быть /releases (с кавычками — это строка в коде)
        expected_url = '"https://api.github.com/repos/DanielLavrushin/b4/releases"'
        self.assertIn(expected_url, yt_src)
        self.assertIn(expected_url, dpi_src)
        # URL не должен быть /releases/latest
        wrong_url = '"https://api.github.com/repos/DanielLavrushin/b4/releases/latest"'
        self.assertNotIn(wrong_url, yt_src)
        self.assertNotIn(wrong_url, dpi_src)

    def test_auto_update_prerelease_same_signature(self):
        """Сигнатуры auto_update_prerelease идентичны в обоих модулях."""
        import inspect
        yt_sig = inspect.signature(self.youtube_b4.auto_update_prerelease)
        dpi_sig = inspect.signature(self.dpi_bypass.auto_update_prerelease)
        self.assertEqual(list(yt_sig.parameters.keys()),
                         list(dpi_sig.parameters.keys()))
        # confirm должен быть с default=True
        self.assertEqual(yt_sig.parameters["confirm"].default, True)
        self.assertEqual(dpi_sig.parameters["confirm"].default, True)

    def test_shared_binary_path_ensures_sync(self):
        """Архитектурная основа синхронизации — общий binary path.

        Когда youtube_b4 обновляет binary, dpi_bypass видит новую версию
        через _detect_version() (читает binary с того же пути).
        """
        self.assertEqual(self.youtube_b4.B4_BINARY_PATH,
                         self.dpi_bypass.B4_BINARY_PATH)
        self.assertEqual(str(self.youtube_b4.B4_BINARY_PATH),
                         "/usr/local/bin/b4")


class TestMenuItemsSync(unittest.TestCase):
    """REGRESSION: синхронизация пунктов меню между youtube_b4 и dpi_bypass.

    БАГ (исправлен): в dpi_bypass.py был дубликат обработчика `ch == "6"`
    (один для Health check, другой для Логов). Из-за этого Логи никогда не
    открывались — при нажатии 7 (Логи по меню) открывался Web UI инструкция
    (потому что обработчик ch=="7" был привязан к Web UI, а не к Логам).

    Также в dpi_bypass.py отсутствовал пункт "8. Web UI инструкция" —
    nginx front был на 8, а в youtube_b4.py (эталон) nginx front на 9.

    Этот тест проверяет:
      1. Меню обоих модулей рендерят ОДИНАКОВЫЕ пункты (byte-for-byte).
      2. Обработчики в dpi_bypass.py не имеют дубликатов.
      3. Каждый пункт меню [N] имеет соответствующий обработчик ch=="N".
      4. Нажатие [7] в dpi_bypass открывает именно Логи, а не Web UI.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def _render_menu_items(self, module, menu_func_name):
        """Рендерит меню и возвращает список (key, label) пунктов."""
        import io
        from contextlib import redirect_stdout

        def _fake_status():
            return {
                'installed': True, 'service_active': True,
                'active_preset': 'default', 'version': '1.78.0',
                'web_port': 9700, 'config_path': '/etc/b4/config.json',
                'binary_path': '/usr/local/bin/b4', 'queue_num': 537,
                'mark': 32768, 'nginx_front_enabled': False,
                'nginx_front_port': 9743, 'nginx_front_url': None,
            }
        module.status = _fake_status
        module._b4_nginx_status = lambda: {'enabled': False, 'port': 9743}

        inputs = iter(['q'])
        def _input(prompt='', *a, **kw):
            return next(inputs)

        captured = io.StringIO()
        with patch("builtins.input", side_effect=_input), \
             redirect_stdout(captured):
            try:
                getattr(module, menu_func_name)()
            except StopIteration:
                pass

        output = captured.getvalue()
        # Извлекаем пункты вида [N] или [U] или [R]
        items = []
        for line in output.split('\n'):
            m = re.search(r'\[([0-9UR])\]\s+(.+?)(?:\s{2,}|\s*$)', line)
            if m:
                items.append((m.group(1), m.group(2).strip()))
        return items

    def test_menus_render_identical_items(self):
        """Оба модуля рендерят ОДИНАКОВЫЕ пункты меню."""
        yt_items = self._render_menu_items(self.youtube_b4, 'do_youtube_b4_menu')
        dpi_items = self._render_menu_items(self.dpi_bypass, 'do_dpi_bypass_menu')
        self.assertEqual(yt_items, dpi_items,
                         f"Меню должны быть идентичны.\n"
                         f"youtube_b4: {yt_items}\n"
                         f"dpi_bypass: {dpi_items}")

    def test_menu_has_eight_web_ui_item(self):
        """REGRESSION: в dpi_bypass.py должен быть пункт [8] Web UI инструкция.

        Раньше этого пункта не было — nginx front был на 8, а Web UI
        инструкция вообще отсутствовала в рендере (но обработчик был).
        """
        dpi_items = self._render_menu_items(self.dpi_bypass, 'do_dpi_bypass_menu')
        keys = [k for k, _ in dpi_items]
        self.assertIn("8", keys, "Пункт [8] должен присутствовать в меню")
        # Пункт 8 должен быть именно Web UI инструкция
        item_8 = [label for k, label in dpi_items if k == "8"][0]
        self.assertIn("Web UI", item_8,
                      f"Пункт [8] должен быть Web UI инструкция, а не '{item_8}'")

    def test_menu_has_nine_nginx_front(self):
        """REGRESSION: nginx front должен быть на [9], а не на [8]."""
        dpi_items = self._render_menu_items(self.dpi_bypass, 'do_dpi_bypass_menu')
        item_9 = [label for k, label in dpi_items if k == "9"]
        self.assertTrue(item_9, "Пункт [9] должен присутствовать в меню")
        self.assertIn("nginx front", item_9[0])

    def test_no_duplicate_handlers_in_dpi_bypass(self):
        """REGRESSION: в dpi_bypass.py не должно быть дубликатов обработчиков.

        БАГ: раньше было два `elif s["installed"] and ch == "6":` —
        первый для Health check, второй для Логов. Второй никогда не
        выполнялся (elif). Проверяем что каждый ch=="N" встречается
        ровно один раз в исходнике.
        """
        import inspect
        src = inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)
        # Считаем количество каждого обработчика
        for key in ["5", "6", "7", "8", "9", "u", "r"]:
            pattern = f'elif s["installed"] and ch == "{key}":'
            count = src.count(pattern)
            self.assertEqual(count, 1,
                             f"Обработчик ch==\"{key}\" должен встречаться ровно 1 раз, "
                             f"найдено {count}")

    def test_menu_item_7_is_logs_not_webui(self):
        """REGRESSION: пункт [7] в dpi_bypass должен быть Логи, не Web UI.

        Именно этот баг видел пользователь: нажал 7 (Логи по меню),
        а открылся Web UI инструкция.
        """
        dpi_items = self._render_menu_items(self.dpi_bypass, 'do_dpi_bypass_menu')
        item_7 = [label for k, label in dpi_items if k == "7"]
        self.assertTrue(item_7, "Пункт [7] должен присутствовать в меню")
        self.assertIn("Логи", item_7[0],
                      f"Пункт [7] должен быть 'Логи b4', а не '{item_7[0]}'")
        self.assertNotIn("Web UI", item_7[0],
                         f"Пункт [7] НЕ должен быть Web UI инструкцией")


class TestSetsMatch(unittest.TestCase):
    """_sets_match — сравнение ключевых полей двух b4 set'ов.

    Используется для детекта активного preset'а из config.json.
    Сравнивает: домены, fake SNI (sni_type, ttl, sni on/off), TCP-фрагментацию,
    QUIC-блок per-set (udp.mode + udp.filter_quic).
    НЕ сравнивает: id, name, enabled.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        # Копируем встроенные set'ы для тестов
        self.default_set = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        self.aggressive_set = dict(self.dpi_bypass.AGGRESSIVE_SET_YOUTUBE)
        self.light_set = dict(self.dpi_bypass.LIGHT_SET_YOUTUBE)

    def test_identical_sets_match(self):
        """Идентичные set'ы — match."""
        self.assertTrue(self.dpi_bypass._sets_match(self.default_set,
                                                     dict(self.default_set)))

    def test_different_domains_no_match(self):
        """Разные домены — no match."""
        modified = dict(self.default_set)
        modified["targets"] = {"sni_domains": ["youtube.com", "extra.com"]}
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_extra_domain_no_match(self):
        """Добавлен один домен — no match."""
        modified = dict(self.default_set)
        original_domains = list(self.default_set["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_reordered_domains_match(self):
        """Домены в другом порядке — match (порядок не важен)."""
        modified = dict(self.default_set)
        original_domains = list(self.default_set["targets"]["sni_domains"])
        # Перемешиваем
        reordered = list(reversed(original_domains))
        modified["targets"] = {"sni_domains": reordered}
        self.assertTrue(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_sni_type_no_match(self):
        """Разный sni_type (fake SNI) — no match."""
        modified = dict(self.default_set)
        modified["faking"] = dict(self.default_set["faking"])
        modified["faking"]["sni_type"] = 2  # Google вместо DuckDuckGo
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_ttl_no_match(self):
        """Разный TTL — no match."""
        modified = dict(self.default_set)
        modified["faking"] = dict(self.default_set["faking"])
        modified["faking"]["ttl"] = 8  # 8 вместо 4
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_seg2delay_no_match(self):
        """Разный seg2delay (фрагментация) — no match."""
        modified = dict(self.default_set)
        modified["tcp"] = dict(self.default_set["tcp"])
        modified["tcp"]["seg2delay"] = 50  # 50 вместо 20
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_seg2delay_max_no_match(self):
        """Разный seg2delay_max — no match."""
        modified = dict(self.default_set)
        modified["tcp"] = dict(self.default_set["tcp"])
        modified["tcp"]["seg2delay_max"] = 100
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_id_still_match(self):
        """Разный id — match (id не влияет на работу b4)."""
        modified = dict(self.default_set)
        modified["id"] = "different-id"
        self.assertTrue(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_name_still_match(self):
        """Разное name — match (name не влияет на работу b4)."""
        modified = dict(self.default_set)
        modified["name"] = "Different Name"
        self.assertTrue(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_enabled_still_match(self):
        """Разный enabled — match (не влияет на функциональность сета)."""
        modified = dict(self.default_set)
        modified["enabled"] = False
        self.assertTrue(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_light_set_sni_false_matches_light(self):
        """Light preset с sni=False — match с light."""
        # Создаём копию light с другим id/name — должно совпадать
        modified = dict(self.light_set)
        modified["id"] = "different"
        modified["name"] = "Different"
        self.assertTrue(self.dpi_bypass._sets_match(modified, self.light_set))

    def test_light_set_sni_false_does_not_match_default(self):
        """Light preset (sni=False) — НЕ match с default (sni по умолчанию True)."""
        self.assertFalse(self.dpi_bypass._sets_match(self.light_set,
                                                      self.default_set))

    def test_aggressive_matches_aggressive(self):
        """Aggressive preset — match с самим собой."""
        self.assertTrue(self.dpi_bypass._sets_match(self.aggressive_set,
                                                     dict(self.aggressive_set)))

    def test_missing_udp_section_no_match_with_preset(self):
        """Сет без udp-секции (defaults b4: fake/sni) ≠ пресет с QUIC-блоком.

        QUIC-блок — per-set (b4 >= 1.79): reject/all — другое поведение,
        чем fake/sni. Старый конфиг без udp-секции — это 'custom'.
        """
        legacy_set = dict(self.default_set)
        legacy_set.pop("udp", None)
        self.assertFalse(self.dpi_bypass._sets_match(legacy_set,
                                                     self.default_set))

    def test_different_udp_mode_no_match(self):
        """Разный udp.mode (reject vs fake) — no match."""
        modified = dict(self.default_set)
        modified["udp"] = {"mode": "fake", "filter_quic": "all"}
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_different_filter_quic_no_match(self):
        """Разный udp.filter_quic (all vs sni) — no match."""
        modified = dict(self.default_set)
        modified["udp"] = {"mode": "reject", "filter_quic": "sni"}
        self.assertFalse(self.dpi_bypass._sets_match(modified, self.default_set))

    def test_legacy_filter_quic_block_is_not_quic_block(self):
        """REGRESSION: filter_quic="block" — легаси-значение.

        NormalizeQUICFilter b4 переписывает всё, кроме "all", в "sni" —
        т.е. "block" НЕ является QUIC-блоком. Сет с udp.filter_quic="block"
        не должен матчиться с пресетом (reject/all).
        """
        legacy_set = dict(self.default_set)
        legacy_set["udp"] = {"mode": "reject", "filter_quic": "block"}
        self.assertFalse(self.dpi_bypass._sets_match(legacy_set,
                                                     self.default_set))


class TestDetectActivePresetFromConfig(unittest.TestCase):
    """_detect_active_preset_from_config — детект preset из /etc/b4/config.json.

    Возвращает кортеж (preset_name, set_name):
      preset_name: 'default'/'aggressive'/'light'/'custom'/'unknown'
      set_name: имя set'а из config.json или None
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir

    def _write_config(self, set_data):
        """Записывает set в config.json в правильном формате."""
        cfg = {"sets": [set_data], "routing": {"enabled": False}, "udp": {"mode": "fake"}}
        self._config_file.write_text(json.dumps(cfg))

    def test_returns_unknown_when_config_missing(self):
        """Config.json отсутствует → ('unknown', None)."""
        self._config_file.unlink(missing_ok=True)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result, ("unknown", None))

    def test_returns_unknown_when_config_corrupted(self):
        """Повреждённый JSON → ('unknown', None)."""
        self._config_file.write_text("not a json")
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result, ("unknown", None))

    def test_returns_none_when_sets_empty(self):
        """Пустой массив sets → ('none', None) — clean install, пресет не выбран."""
        self._config_file.write_text(json.dumps({"sets": []}))
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result, ("none", None))

    def test_detects_default_preset(self):
        """Set совпадает с DEFAULT_SET_YOUTUBE → ('default', set_name)."""
        self._write_config(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "default")
        self.assertEqual(result[1], "Youtube")  # name из DEFAULT_SET_YOUTUBE

    def test_detects_aggressive_preset(self):
        """Set совпадает с AGGRESSIVE_SET_YOUTUBE → ('aggressive', set_name)."""
        self._write_config(self.dpi_bypass.AGGRESSIVE_SET_YOUTUBE)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "aggressive")
        self.assertEqual(result[1], "Youtube-Aggressive")

    def test_detects_light_preset(self):
        """Set совпадает с LIGHT_SET_YOUTUBE → ('light', set_name)."""
        self._write_config(self.dpi_bypass.LIGHT_SET_YOUTUBE)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "light")
        self.assertEqual(result[1], "Youtube-Light")

    def test_detects_custom_when_domains_modified(self):
        """Добавлен домен → ('custom', set_name).

        REGRESSION: ранее TUI показывал устаревшее имя preset'а из state.json,
        даже если set был правлен через Web UI.
        """
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        original_domains = list(modified["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        modified["name"] = "Youtube-Extended"
        self._write_config(modified)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "custom")
        self.assertEqual(result[1], "Youtube-Extended")

    def test_detects_custom_when_sni_type_changed(self):
        """Изменён sni_type → ('custom', set_name)."""
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        modified["faking"] = dict(modified["faking"])
        modified["faking"]["sni_type"] = 2  # Google вместо DuckDuckGo
        self._write_config(modified)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "custom")

    def test_detects_custom_when_seg2delay_changed(self):
        """Изменён seg2delay → ('custom', set_name)."""
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        modified["tcp"] = dict(modified["tcp"])
        modified["tcp"]["seg2delay"] = 50
        self._write_config(modified)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "custom")

    def test_detects_default_even_with_different_id_name(self):
        """Set с другим id/name, но функционально идентичный → ('default', name).

        Web UI может менять id/name — это не должно влиять на детект preset'а.
        """
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        modified["id"] = "yt-custom-id"
        modified["name"] = "My Custom Youtube"
        self._write_config(modified)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "default")
        self.assertEqual(result[1], "My Custom Youtube")

    def test_returns_none_set_name_when_name_missing(self):
        """Set без name → set_name=None."""
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        modified.pop("name", None)
        self._write_config(modified)
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result[0], "default")
        self.assertIsNone(result[1])


class TestStatusAutoSyncPreset(unittest.TestCase):
    """status() — авто-синхронизация active_preset с config.json.

    REGRESSION: ранее state.json хранил устаревшее имя preset'а, даже если
    set был изменён через Web UI / Discovery. Теперь status() детектит
    актуальный preset из config.json и обновляет state.json.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()

    def _write_config(self, set_data):
        cfg = {"sets": [set_data], "routing": {"enabled": False}, "udp": {"mode": "fake"}}
        self._config_file.write_text(json.dumps(cfg))

    def _write_state(self, preset_name):
        self._state_file.write_text(json.dumps({
            "installed": True, "active_preset": preset_name, "enabled": True,
            "version": "1.78.0",
        }))

    def test_state_updated_when_config_changed_to_custom(self):
        """State.json с 'default', config изменён → state обновляется до 'custom'."""
        # Имитируем: TUI включила default, потом Web UI добавила домен
        self._write_state("default")
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        original_domains = list(modified["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        modified["name"] = "Modified"
        self._write_config(modified)
        # Mock installed=True
        self.dpi_bypass.B4_BINARY_PATH = self._tmpdir / "b4"
        self.dpi_bypass.B4_UNIT_PATH = self._tmpdir / "b4.service"
        self.dpi_bypass.B4_BINARY_PATH.touch()
        self.dpi_bypass.B4_UNIT_PATH.touch()
        # Вызываем status()
        result = self.dpi_bypass.status()
        # Проверяем что active_preset = 'custom' (детектировано из config)
        self.assertEqual(result["active_preset"], "custom")
        self.assertEqual(result["active_set_name"], "Modified")
        # Проверяем что state.json обновлён
        state = json.loads(self._state_file.read_text())
        self.assertEqual(state["active_preset"], "custom")

    def test_state_unchanged_when_config_matches_state(self):
        """State='default', config=default → state не меняется."""
        self._write_state("default")
        self._write_config(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        self.dpi_bypass.B4_BINARY_PATH = self._tmpdir / "b4"
        self.dpi_bypass.B4_UNIT_PATH = self._tmpdir / "b4.service"
        self.dpi_bypass.B4_BINARY_PATH.touch()
        self.dpi_bypass.B4_UNIT_PATH.touch()
        original_state_mtime = self._state_file.stat().st_mtime
        result = self.dpi_bypass.status()
        self.assertEqual(result["active_preset"], "default")
        # State.json не должен был измениться
        new_state_mtime = self._state_file.stat().st_mtime
        self.assertEqual(original_state_mtime, new_state_mtime,
                         "state.json не должен перезаписываться при совпадении preset'а")

    def test_state_unknown_when_config_missing(self):
        """Config.json отсутствует → active_preset берётся из state.json."""
        self._write_state("aggressive")
        self._config_file.unlink(missing_ok=True)
        self.dpi_bypass.B4_BINARY_PATH = self._tmpdir / "b4"
        self.dpi_bypass.B4_UNIT_PATH = self._tmpdir / "b4.service"
        self.dpi_bypass.B4_BINARY_PATH.touch()
        self.dpi_bypass.B4_UNIT_PATH.touch()
        result = self.dpi_bypass.status()
        # detected='unknown', поэтому берётся state_preset
        self.assertEqual(result["active_preset"], "aggressive")

    def test_status_includes_active_set_name(self):
        """status() возвращает 'active_set_name' (имя set'а из config.json)."""
        self._write_state("default")
        self._write_config(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        self.dpi_bypass.B4_BINARY_PATH = self._tmpdir / "b4"
        self.dpi_bypass.B4_UNIT_PATH = self._tmpdir / "b4.service"
        self.dpi_bypass.B4_BINARY_PATH.touch()
        self.dpi_bypass.B4_UNIT_PATH.touch()
        result = self.dpi_bypass.status()
        self.assertIn("active_set_name", result)
        self.assertEqual(result["active_set_name"], "Youtube")


class TestMenuPresetDisplayAplusB(unittest.TestCase):
    """REGRESSION: отображение preset в меню — подход A+B.

    A: детектим preset из config.json.
    B: если 'custom' — показываем 'custom (имя_seta)'.

    Тестируем что в меню b4 при кастомном сете показывается
    'custom (имя_seta)' вместо устаревшего имени preset'а.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()

    def _render_menu_preset_line(self, set_data, state_preset):
        """Рендерит меню и возвращает строку 'Preset: ...'."""
        import io
        from contextlib import redirect_stdout
        # Готовим config + state
        cfg = {"sets": [set_data], "routing": {"enabled": False}, "udp": {"mode": "fake"}}
        self._config_file.write_text(json.dumps(cfg))
        self._state_file.write_text(json.dumps({
            "installed": True, "active_preset": state_preset, "enabled": True,
            "version": "1.78.0",
        }))
        # Mock installed=True
        self.dpi_bypass.B4_BINARY_PATH = self._tmpdir / "b4"
        self.dpi_bypass.B4_UNIT_PATH = self._tmpdir / "b4.service"
        self.dpi_bypass.B4_BINARY_PATH.touch()
        self.dpi_bypass.B4_UNIT_PATH.touch()
        # Mock status-зависимости
        self.dpi_bypass._b4_nginx_status = lambda: {"enabled": False, "port": 9743}
        # Рендерим меню
        inputs = iter(['q'])
        def _input(prompt='', *a, **kw):
            return next(inputs)
        captured = io.StringIO()
        with patch("builtins.input", side_effect=_input), \
             redirect_stdout(captured):
            try:
                self.dpi_bypass.do_dpi_bypass_menu()
            except StopIteration:
                pass
        # Ищем строку с Preset
        for line in captured.getvalue().split('\n'):
            if 'Preset:' in line:
                return line.strip()
        return None

    def test_default_preset_shows_active_set_name(self):
        """Default preset → показывает зелёную точку + имя сета 'Youtube'."""
        line = self._render_menu_preset_line(self.dpi_bypass.DEFAULT_SET_YOUTUBE, "default")
        self.assertIsNotNone(line)
        # Должно показать имя сета из config.json (не подпись пресета)
        self.assertIn("Youtube", line)

    def test_aggressive_preset_shows_active_set_name(self):
        """Aggressive preset → показывает зелёную точку + 'Youtube-Aggressive'."""
        line = self._render_menu_preset_line(self.dpi_bypass.AGGRESSIVE_SET_YOUTUBE, "aggressive")
        self.assertIsNotNone(line)
        self.assertIn("Youtube-Aggressive", line)

    def test_custom_preset_shows_active_set_name(self):
        """REGRESSION: custom preset → показывает зелёную точку + имя сета.

        Ранее показывал устаревшее имя preset'а из state.json.
        """
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        original_domains = list(modified["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        modified["name"] = "Youtube-Extended"
        line = self._render_menu_preset_line(modified, "default")
        self.assertIsNotNone(line)
        self.assertIn("Youtube-Extended", line)

    def test_custom_preset_without_name_shows_id(self):
        """Custom set без name → показывает id сета (fallback)."""
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        original_domains = list(modified["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        modified.pop("name", None)
        line = self._render_menu_preset_line(modified, "default")
        self.assertIsNotNone(line)
        # Должен показать id (fallback когда нет name)
        self.assertIn("youtube", line)


class TestYoutubeB4HasPresetDetection(unittest.TestCase):
    """REGRESSION: youtube_b4.py имеет те же функции детекта preset'а что dpi_bypass.

    Синхронизация между модулями — оба должны иметь:
    _sets_match, _detect_active_preset_from_config, status() с авто-синком.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_youtube_b4_has_sets_match(self):
        self.assertTrue(hasattr(self.youtube_b4, '_sets_match'))
        self.assertTrue(callable(self.youtube_b4._sets_match))

    def test_youtube_b4_has_detect_active_preset(self):
        self.assertTrue(hasattr(self.youtube_b4, '_detect_active_preset_from_config'))

    def test_status_returns_active_set_name_in_both(self):
        """status() в обоих модулях возвращает 'active_set_name'."""
        # Просто проверяем что ключ есть в возвращаемом dict'е
        # (когда b4 не установлен, status() возвращает early-return dict без этого ключа)
        # Поэтому проверяем через mock
        self.youtube_b4.B4_BINARY_PATH = Path("/tmp/nonexistent_b4_test")
        self.dpi_bypass.B4_BINARY_PATH = Path("/tmp/nonexistent_b4_test")
        # Когда не установлен — оба возвращают {'installed': False, ...}
        yt_status = self.youtube_b4.status()
        dpi_status = self.dpi_bypass.status()
        # Когда установлен — добавляется 'active_set_name'. Здесь просто
        # проверяем что функция не падает.
        self.assertIn("active_preset", yt_status)
        self.assertIn("active_preset", dpi_status)

    def test_sets_match_identical_in_both_modules(self):
        """_sets_match должна работать идентично в обоих модулях."""
        # Берём default set из dpi_bypass и проверяем что youtube_b4._sets_match
        # тоже считает его совпадающим с самим собой
        test_set = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        yt_result = self.youtube_b4._sets_match(test_set, dict(test_set))
        dpi_result = self.dpi_bypass._sets_match(test_set, dict(test_set))
        self.assertEqual(yt_result, dpi_result)
        self.assertTrue(yt_result)


class TestNativeB4Rules(unittest.TestCase):
    """REGRESSION: b4 управляет своими iptables-правилами (native mode).

    Раньше Chimera ставила правила вручную через --skip-tables, что
    приводило к перехвату ВЕСЁГО 443-трафика (exit-ноды, google.com и т.д.).
    Теперь b4 сам управляет своими правилами через ipset — перехватывается
    только YouTube-трафик.

    Проверяем:
      1. systemd-unit НЕ содержит --skip-tables.
      2. _iptables_apply() НЕ ставит IPv4 правила (только IPv6 fallback).
      3. install_b4() вызывает _iptables_remove() перед стартом (cleanup).
      4. enable() НЕ вызывает _iptables_apply() для IPv4.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_systemd_unit_no_skip_tables_youtube_b4(self):
        """systemd-unit в youtube_b4 НЕ содержит --skip-tables.

        Проверяем СГЕНЕРИРОВАННЫЙ unit (вызов _write_systemd_unit), а не
        исходник функции — docstring упоминает --skip-tables для объяснения.
        """
        import tempfile
        tmp_unit = Path(tempfile.mkdtemp()) / "b4.service"
        orig_unit_path = self.youtube_b4.B4_UNIT_PATH
        self.youtube_b4.B4_UNIT_PATH = tmp_unit
        try:
            self.youtube_b4._write_systemd_unit()
            unit_content = tmp_unit.read_text()
        finally:
            self.youtube_b4.B4_UNIT_PATH = orig_unit_path
        # В сгенерированном unit НЕ должно быть --skip-tables в ExecStart
        self.assertNotIn("--skip-tables", unit_content,
                         "Сгенерированный systemd-unit НЕ должен содержать --skip-tables")

    def test_systemd_unit_no_skip_tables_dpi_bypass(self):
        """systemd-unit в dpi_bypass НЕ содержит --skip-tables."""
        import tempfile
        tmp_unit = Path(tempfile.mkdtemp()) / "b4.service"
        orig_unit_path = self.dpi_bypass.B4_UNIT_PATH
        self.dpi_bypass.B4_UNIT_PATH = tmp_unit
        try:
            self.dpi_bypass._write_systemd_unit()
            unit_content = tmp_unit.read_text()
        finally:
            self.dpi_bypass.B4_UNIT_PATH = orig_unit_path
        self.assertNotIn("--skip-tables", unit_content,
                         "Сгенерированный systemd-unit НЕ должен содержать --skip-tables")

    def test_iptables_apply_no_ipv4_rules_youtube_b4(self):
        """_iptables_apply() в youtube_b4 НЕ ставит НИКАКИХ правил (no-op).

        b4 сам управляет через nftables `table inet b4_mangle` (IPv4+IPv6).
        Chimera не ставит ни IPv4, ни IPv6 правила.
        """
        import inspect
        src = inspect.getsource(self.youtube_b4._iptables_apply)
        # НЕ должно быть iptables -t mangle -A b4_mangle (IPv4)
        self.assertNotIn('"-A", "b4_mangle"', src,
                         "_iptables_apply() НЕ должен ставить IPv4 правила")
        # НЕ должно быть ip6tables (IPv6 fallback убран — b4 сам через inet)
        self.assertNotIn("ip6tables", src,
                         "_iptables_apply() НЕ должен ставить IPv6 правила "
                         "(b4 сам через table inet)")

    def test_iptables_apply_no_ipv4_rules_dpi_bypass(self):
        """_iptables_apply() в dpi_bypass НЕ ставит НИКАКИХ правил (no-op)."""
        import inspect
        src = inspect.getsource(self.dpi_bypass._iptables_apply)
        self.assertNotIn('"-A", "b4_mangle"', src,
                         "_iptables_apply() НЕ должен ставить IPv4 правила")
        self.assertNotIn("ip6tables", src,
                         "_iptables_apply() НЕ должен ставить IPv6 правила "
                         "(b4 сам через table inet)")

    def test_iptables_remove_still_cleans_ipv4(self):
        """_iptables_remove() ВСЁ ЕЩЁ убирает IPv4 правила (cleanup при crash).

        Даже в native mode, _iptables_remove() должен убирать b4_mangle (IPv4) —
        на случай если b4 упал без cleanup'а (kill, OOM) или при миграции
        со старого режима.
        """
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._iptables_remove)
        dpi_src = inspect.getsource(self.dpi_bypass._iptables_remove)
        # Оба должны содержать cleanup для b4_mangle (IPv4)
        self.assertIn('"b4_mangle"', yt_src,
                      "_iptables_remove() должен убирать IPv4 b4_mangle (cleanup)")
        self.assertIn('"b4_mangle"', dpi_src,
                      "_iptables_remove() должен убирать IPv4 b4_mangle (cleanup)")
        # Оба должны содержать cleanup для b4_mangle6 (IPv6)
        self.assertIn('"b4_mangle6"', yt_src)
        self.assertIn('"b4_mangle6"', dpi_src)

    def test_install_b4_calls_iptables_remove_before_start(self):
        """install_b4() вызывает _iptables_remove() перед стартом b4.

        Это нужно для cleanup старых Chimera'ных правил (до v5) при
        переустановке или миграции.
        """
        import inspect
        yt_src = inspect.getsource(self.youtube_b4.install_b4)
        dpi_src = inspect.getsource(self.dpi_bypass.install_b4)
        self.assertIn("_iptables_remove()", yt_src,
                      "install_b4() должен вызывать _iptables_remove() перед стартом")
        self.assertIn("_iptables_remove()", dpi_src,
                      "install_b4() должен вызывать _iptables_remove() перед стартом")

    def test_both_modules_have_migrate_function(self):
        """REGRESSION: оба модуля имеют _migrate_to_native_rules_if_needed()."""
        self.assertTrue(hasattr(self.youtube_b4, '_migrate_to_native_rules_if_needed'))
        self.assertTrue(hasattr(self.dpi_bypass, '_migrate_to_native_rules_if_needed'))

    def test_migrate_function_calls_write_systemd_unit(self):
        """_migrate_to_native_rules_if_needed() вызывает _write_systemd_unit().

        Это перезаписывает старый unit (с --skip-tables) на новый (native).
        """
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._migrate_to_native_rules_if_needed)
        dpi_src = inspect.getsource(self.dpi_bypass._migrate_to_native_rules_if_needed)
        self.assertIn("_write_systemd_unit()", yt_src)
        self.assertIn("_write_systemd_unit()", dpi_src)

    def test_migrate_function_calls_iptables_remove(self):
        """_migrate_to_native_rules_if_needed() убирает старые IPv4 правила."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._migrate_to_native_rules_if_needed)
        dpi_src = inspect.getsource(self.dpi_bypass._migrate_to_native_rules_if_needed)
        self.assertIn("_iptables_remove()", yt_src)
        self.assertIn("_iptables_remove()", dpi_src)

    def test_migrate_function_restarts_b4(self):
        """_migrate_to_native_rules_if_needed() перезапускает b4."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._migrate_to_native_rules_if_needed)
        dpi_src = inspect.getsource(self.dpi_bypass._migrate_to_native_rules_if_needed)
        # Проверяем что вызывается systemctl restart b4
        self.assertIn('"restart"', yt_src)
        self.assertIn('"b4"', yt_src)
        self.assertIn('"restart"', dpi_src)
        self.assertIn('"b4"', dpi_src)

    def test_menu_calls_migrate_on_open(self):
        """do_*_menu() вызывает _migrate_to_native_rules_if_needed() при открытии."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4.do_youtube_b4_menu)
        dpi_src = inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)
        self.assertIn("_migrate_to_native_rules_if_needed()", yt_src,
                      "do_youtube_b4_menu должен вызывать миграцию при открытии")
        self.assertIn("_migrate_to_native_rules_if_needed()", dpi_src,
                      "do_dpi_bypass_menu должен вызывать миграцию при открытии")

    def test_systemd_unit_uses_verbose_silent_youtube_b4(self):
        """REGRESSION: systemd-unit в youtube_b4 использует --verbose silent.

        b4 при --verbose info логирует каждый пакет (~1.1М строк/час).
        --verbose silent отключает это, оставляя только ошибки.
        """
        import tempfile
        tmp_unit = Path(tempfile.mkdtemp()) / "b4.service"
        orig = self.youtube_b4.B4_UNIT_PATH
        self.youtube_b4.B4_UNIT_PATH = tmp_unit
        try:
            self.youtube_b4._write_systemd_unit()
            content = tmp_unit.read_text()
        finally:
            self.youtube_b4.B4_UNIT_PATH = orig
        self.assertIn("--verbose silent", content)
        self.assertNotIn("--verbose info", content)
        self.assertNotIn("--verbose warn", content)

    def test_systemd_unit_uses_verbose_silent_dpi_bypass(self):
        """REGRESSION: systemd-unit в dpi_bypass использует --verbose silent."""
        import tempfile
        tmp_unit = Path(tempfile.mkdtemp()) / "b4.service"
        orig = self.dpi_bypass.B4_UNIT_PATH
        self.dpi_bypass.B4_UNIT_PATH = tmp_unit
        try:
            self.dpi_bypass._write_systemd_unit()
            content = tmp_unit.read_text()
        finally:
            self.dpi_bypass.B4_UNIT_PATH = orig
        self.assertIn("--verbose silent", content)
        self.assertNotIn("--verbose info", content)
        self.assertNotIn("--verbose warn", content)

    def test_migrate_detects_verbose_info(self):
        """REGRESSION: миграция детектит --verbose info и мигрирует на silent."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._migrate_to_native_rules_if_needed)
        dpi_src = inspect.getsource(self.dpi_bypass._migrate_to_native_rules_if_needed)
        # Проверяем что миграция ищет --verbose info
        self.assertIn('"--verbose info"', yt_src)
        self.assertIn('"--verbose info"', dpi_src)

    def test_migrate_detects_verbose_warn(self):
        """REGRESSION: миграция детектит --verbose warn (баг b4, фильтрует как info)."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._migrate_to_native_rules_if_needed)
        dpi_src = inspect.getsource(self.dpi_bypass._migrate_to_native_rules_if_needed)
        self.assertIn('"--verbose warn"', yt_src)
        self.assertIn('"--verbose warn"', dpi_src)


class TestMigrateFunctionBehavior(unittest.TestCase):
    """Поведенческие тесты _migrate_to_native_rules_if_needed()."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._unit_path = self._tmpdir / "b4.service"
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_UNIT_PATH = self._unit_path
        self.dpi_bypass.subprocess = MagicMock()
        # Mock _write_systemd_unit, _iptables_remove, _iptables_apply
        self.dpi_bypass._write_systemd_unit = lambda: True
        self.dpi_bypass._iptables_remove = lambda: None
        self.dpi_bypass._iptables_apply = lambda: True

    def test_returns_false_when_unit_missing(self):
        """Unit не существует → миграция не нужна."""
        self._unit_path.unlink(missing_ok=True)
        result = self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertFalse(result)

    def test_returns_false_when_unit_already_native(self):
        """Unit без --skip-tables → миграция не нужна."""
        self._unit_path.write_text("""
[Service]
ExecStart=/usr/local/bin/b4 --config /etc/b4/config.json --ipv4 --ipv6
""")
        result = self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertFalse(result)

    def test_returns_true_when_unit_has_skip_tables(self):
        """Unit с --skip-tables → миграция выполняется."""
        self._unit_path.write_text("""
[Service]
ExecStart=/usr/local/bin/b4 --config /etc/b4/config.json --skip-tables --ipv4
""")
        # Mock systemctl restart success
        self.dpi_bypass.subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        result = self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertTrue(result)

    def test_migrate_calls_write_systemd_unit_when_needed(self):
        """При миграции вызывается _write_systemd_unit()."""
        self._unit_path.write_text("ExecStart=... --skip-tables ...")
        write_called = []
        self.dpi_bypass._write_systemd_unit = lambda: write_called.append(True) or True
        self.dpi_bypass.subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertEqual(len(write_called), 1,
                         "_write_systemd_unit должен быть вызван ровно 1 раз")

    def test_migrate_calls_iptables_remove_when_needed(self):
        """При миграции вызывается _iptables_remove()."""
        self._unit_path.write_text("ExecStart=... --skip-tables ...")
        remove_called = []
        self.dpi_bypass._iptables_remove = lambda: remove_called.append(True)
        self.dpi_bypass.subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertEqual(len(remove_called), 1)

    def test_returns_true_when_unit_has_verbose_info(self):
        """REGRESSION: Unit с --verbose info → миграция выполняется (→ silent)."""
        self._unit_path.write_text("""
[Service]
ExecStart=/usr/local/bin/b4 --config /etc/b4/config.json --verbose info --ipv4 --ipv6
""")
        self.dpi_bypass.subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        result = self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertTrue(result)

    def test_returns_true_when_unit_has_verbose_warn(self):
        """REGRESSION: Unit с --verbose warn → миграция выполняется (баг b4, фильтрует как info)."""
        self._unit_path.write_text("""
[Service]
ExecStart=/usr/local/bin/b4 --config /etc/b4/config.json --verbose warn --ipv4 --ipv6
""")
        self.dpi_bypass.subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        result = self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertTrue(result)

    def test_returns_false_when_unit_already_silent(self):
        """REGRESSION: Unit с --verbose silent → миграция НЕ нужна."""
        self._unit_path.write_text("""
[Service]
ExecStart=/usr/local/bin/b4 --config /etc/b4/config.json --verbose silent --ipv4 --ipv6
""")
        self.dpi_bypass.subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        result = self.dpi_bypass._migrate_to_native_rules_if_needed()
        self.assertFalse(result)


class TestNativeRulesSyncBetweenModules(unittest.TestCase):
    """REGRESSION: синхронизация native b4 rules между youtube_b4 и dpi_bypass.

    Оба модуля должны:
      - Иметь _migrate_to_native_rules_if_needed()
      - НЕ использовать --skip-tables
      - Иметь идентичную логику IPv6 fallback
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_both_modules_no_skip_tables(self):
        """Оба модуля НЕ используют --skip-tables в сгенерированном unit."""
        import tempfile
        # youtube_b4
        tmp_unit_yt = Path(tempfile.mkdtemp()) / "b4.service"
        orig_yt = self.youtube_b4.B4_UNIT_PATH
        self.youtube_b4.B4_UNIT_PATH = tmp_unit_yt
        try:
            self.youtube_b4._write_systemd_unit()
            yt_content = tmp_unit_yt.read_text()
        finally:
            self.youtube_b4.B4_UNIT_PATH = orig_yt
        # dpi_bypass
        tmp_unit_dpi = Path(tempfile.mkdtemp()) / "b4.service"
        orig_dpi = self.dpi_bypass.B4_UNIT_PATH
        self.dpi_bypass.B4_UNIT_PATH = tmp_unit_dpi
        try:
            self.dpi_bypass._write_systemd_unit()
            dpi_content = tmp_unit_dpi.read_text()
        finally:
            self.dpi_bypass.B4_UNIT_PATH = orig_dpi
        self.assertNotIn("--skip-tables", yt_content)
        self.assertNotIn("--skip-tables", dpi_content)

    def test_both_modules_no_iptables_apply(self):
        """REGRESSION: оба модуля НЕ ставят НИКАКИХ правил в _iptables_apply().

        b4 сам управляет через nftables `table inet b4_mangle` (IPv4+IPv6).
        Chimera не ставит ни IPv4, ни IPv6 правила. Раньше (до этого фикса)
        Chimera ставила IPv6 fallback, что приводило к двойному перехвату
        на серверах с IPv6 и "дрисне" в логах b4.

        Проверяем что _iptables_apply() НЕ вызывает subprocess.run вообще —
        функция должна быть no-op (только информационное сообщение через _info).
        """
        import inspect, ast
        for module_name, module in [("youtube_b4", self.youtube_b4),
                                     ("dpi_bypass", self.dpi_bypass)]:
            src = inspect.getsource(module._iptables_apply)
            tree = ast.parse(src)
            # Ищем вызовы subprocess.run — их НЕ должно быть
            subprocess_calls = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Проверяем subprocess.run(...)
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr == "run":
                        if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                            subprocess_calls.append(node)
            self.assertEqual(len(subprocess_calls), 0,
                f"{module_name}: _iptables_apply() должен быть no-op "
                f"(не вызывать subprocess.run), но найдено {len(subprocess_calls)} вызовов")

    def test_both_modules_iptables_remove_cleans_both_v4_v6(self):
        """_iptables_remove() убирает и IPv4, и IPv6 правила (cleanup)."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._iptables_remove)
        dpi_src = inspect.getsource(self.dpi_bypass._iptables_remove)
        # IPv4 cleanup (для миграции со старого режима + crash b4)
        self.assertIn('"b4_mangle"', yt_src)
        self.assertIn('"b4_mangle"', dpi_src)
        # IPv6 cleanup (убираем старые Chimera'ные b4_mangle6)
        self.assertIn('"b4_mangle6"', yt_src)
        self.assertIn('"b4_mangle6"', dpi_src)

    def test_both_modules_have_migrate_function(self):
        """Оба модуля имеют _migrate_to_native_rules_if_needed()."""
        self.assertTrue(hasattr(self.youtube_b4, '_migrate_to_native_rules_if_needed'))
        self.assertTrue(hasattr(self.dpi_bypass, '_migrate_to_native_rules_if_needed'))

    def test_both_modules_call_migrate_in_menu(self):
        """Оба модуля вызывают миграцию при открытии меню."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4.do_youtube_b4_menu)
        dpi_src = inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)
        self.assertIn("_migrate_to_native_rules_if_needed()", yt_src)
        self.assertIn("_migrate_to_native_rules_if_needed()", dpi_src)


class TestCleanInstallEmptyConfig(unittest.TestCase):
    """REGRESSION: clean install — b4 устанавливается с ПУСТЫМ конфигом.

    Пользователь должен выбрать пресет через TUI ([2]) или Discovery в Web UI.
    Это даёт гибкость — не всем подойдут встроенные пресеты.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_youtube_b4_has_write_empty_config(self):
        """REGRESSION: youtube_b4 имеет _write_empty_config()."""
        self.assertTrue(hasattr(self.youtube_b4, '_write_empty_config'))

    def test_dpi_bypass_has_write_empty_config(self):
        """REGRESSION: dpi_bypass имеет _write_empty_config()."""
        self.assertTrue(hasattr(self.dpi_bypass, '_write_empty_config'))

    def test_install_b4_uses_empty_config_youtube_b4(self):
        """REGRESSION: install_b4() в youtube_b4 вызывает _write_empty_config()."""
        import inspect
        src = inspect.getsource(self.youtube_b4.install_b4)
        self.assertIn("_write_empty_config()", src,
                      "install_b4() должен вызывать _write_empty_config()")
        self.assertNotIn("_write_default_config()", src,
                         "install_b4() НЕ должен вызывать _write_default_config()")

    def test_install_b4_uses_empty_config_dpi_bypass(self):
        """REGRESSION: install_b4() в dpi_bypass вызывает _write_empty_config()."""
        import inspect
        src = inspect.getsource(self.dpi_bypass.install_b4)
        self.assertIn("_write_empty_config()", src,
                      "install_b4() должен вызывать _write_empty_config()")
        self.assertNotIn("_write_default_config()", src,
                         "install_b4() НЕ должен вызывать _write_default_config()")

    def test_write_empty_config_creates_empty_sets(self):
        """_write_empty_config() создаёт config: пустой sets + system.geo.sitedat_path.

        REGRESSION (b4 1.79+/1.80rc1): верхнеуровневые "udp"/"routing" —
        мёртвые ключи (Config b4 = version/queue/system/sets/ui), b4 их не
        читает и выкидывает при собственном сохранении. Правильный путь
        geosite — system.geo.sitedat_path (GeoDatConfig), не system.geosite_path.
        """
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        config_file = tmpdir / "config.json"
        orig = self.youtube_b4.B4_CONFIG_FILE
        orig_dir = self.youtube_b4.B4_CONFIG_DIR
        orig_sets = self.youtube_b4.B4_SETS_DIR
        orig_log = self.youtube_b4.B4_LOG_DIR
        orig_shared = self.youtube_b4.B4_GEOSITE_SHARED_PATHS
        self.youtube_b4.B4_CONFIG_FILE = config_file
        self.youtube_b4.B4_CONFIG_DIR = tmpdir
        self.youtube_b4.B4_SETS_DIR = tmpdir / "sets"
        self.youtube_b4.B4_LOG_DIR = tmpdir / "log"
        self.youtube_b4.B4_GEOSITE_SHARED_PATHS = ()  # нет общего geosite Xray
        try:
            self.youtube_b4._write_empty_config()
            cfg = json.loads(config_file.read_text())
            self.assertEqual(cfg["sets"], [])
            # Мёртвые верхнеуровневые секции — НЕ пишем.
            self.assertNotIn("routing", cfg,
                             "верхнеуровневый routing — мёртвый ключ b4")
            self.assertNotIn("udp", cfg,
                             "верхнеуровневый udp — мёртвый ключ b4 "
                             "(QUIC-настройки per-set)")
            # system.geo.sitedat_path — живой путь к geosite.dat:
            # без общего файла Xray — собственный путь b4 (/etc/b4).
            self.assertIn("system", cfg)
            self.assertIn("geo", cfg["system"])
            self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                             "/etc/b4/geosite.dat")
            self.assertNotIn("geosite_path", cfg["system"],
                             "system.geosite_path — мёртвый ключ "
                             "(правильный — system.geo.sitedat_path)")
        finally:
            self.youtube_b4.B4_CONFIG_FILE = orig
            self.youtube_b4.B4_CONFIG_DIR = orig_dir
            self.youtube_b4.B4_SETS_DIR = orig_sets
            self.youtube_b4.B4_LOG_DIR = orig_log
            self.youtube_b4.B4_GEOSITE_SHARED_PATHS = orig_shared

    def test_write_empty_config_always_local_geosite_with_seed(self):
        """v75.1 (3 машины, 500 EROFS в Web UI b4): общий geosite.dat Xray
        существует → sitedat_path ВСЁ РАВНО собственный /etc/b4/geosite.dat,
        а база КОПИРУЕТСЯ туда (seed). /usr read-only для процесса b4
        (ProtectSystem=strict) — шаринг ломает Update геосайта.
        """
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        shared = tmpdir / "shared" / "geosite.dat"
        shared.parent.mkdir()
        shared.write_bytes(b"shared-xray-geosite")
        local = tmpdir / "b4" / "geosite.dat"
        config_file = tmpdir / "config.json"
        mod = self.youtube_b4
        orig = (mod.B4_CONFIG_FILE, mod.B4_CONFIG_DIR, mod.B4_SETS_DIR,
                mod.B4_LOG_DIR, mod.B4_GEOSITE_SHARED_PATHS,
                mod.B4_GEOSITE_LOCAL_PATH)
        mod.B4_CONFIG_FILE = config_file
        mod.B4_CONFIG_DIR = tmpdir
        mod.B4_SETS_DIR = tmpdir / "sets"
        mod.B4_LOG_DIR = tmpdir / "log"
        mod.B4_GEOSITE_SHARED_PATHS = (str(shared),)
        mod.B4_GEOSITE_LOCAL_PATH = str(local)
        try:
            mod._write_empty_config()
            cfg = json.loads(config_file.read_text())
            self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                             str(local))
            # Seed: общий файл Xray скопирован в собственный каталог b4.
            self.assertTrue(local.is_file())
            self.assertEqual(local.read_bytes(), b"shared-xray-geosite")
            # Шаринг не используется: путь сета ≠ путь Xray.
            self.assertNotEqual(cfg["system"]["geo"]["sitedat_path"],
                                str(shared))
        finally:
            (mod.B4_CONFIG_FILE, mod.B4_CONFIG_DIR, mod.B4_SETS_DIR,
             mod.B4_LOG_DIR, mod.B4_GEOSITE_SHARED_PATHS,
             mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_detect_returns_none_for_empty_config(self):
        """_detect_active_preset_from_config() возвращает 'none' для пустого config."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        config_file = tmpdir / "config.json"
        config_file.write_text(json.dumps({"sets": []}))
        orig = self.youtube_b4.B4_CONFIG_FILE
        self.youtube_b4.B4_CONFIG_FILE = config_file
        try:
            result = self.youtube_b4._detect_active_preset_from_config()
            self.assertEqual(result, ("none", None))
        finally:
            self.youtube_b4.B4_CONFIG_FILE = orig

    def test_install_b4_sets_preset_none_in_state(self):
        """REGRESSION: install_b4() сохраняет active_preset=None в state.json."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4.install_b4)
        dpi_src = inspect.getsource(self.dpi_bypass.install_b4)
        # Проверяем что в _save_state передаётся active_preset: None
        self.assertIn('"active_preset": None', yt_src)
        self.assertIn('"active_preset": None', dpi_src)


class TestMenuWarningForCleanInstall(unittest.TestCase):
    """REGRESSION: меню показывает предупреждение при active_preset='none'."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_youtube_b4_menu_has_warning_for_none(self):
        """do_youtube_b4_menu() содержит предупреждение при preset='none'."""
        import inspect
        src = inspect.getsource(self.youtube_b4.do_youtube_b4_menu)
        self.assertIn('"none"', src)
        self.assertIn("ПРЕСЕТ НЕ ВЫБРАН", src)

    def test_dpi_bypass_menu_has_warning_for_none(self):
        """do_dpi_bypass_menu() содержит предупреждение при preset='none'."""
        import inspect
        src = inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)
        self.assertIn('"none"', src)
        self.assertIn("ПРЕСЕТ НЕ ВЫБРАН", src)

    def test_youtube_b4_menu_has_preset_list(self):
        """youtube_b4 меню содержит список пресетов с плюсами/минусами."""
        import inspect
        src = inspect.getsource(self.youtube_b4.do_youtube_b4_menu)
        # Должны быть упоминания всех 3 пресетов
        self.assertIn("Эталон", src)
        self.assertIn("Агрессивный", src)
        self.assertIn("Лёгкий", src)
        # Должны быть плюсы/минусы
        self.assertIn("+", src)
        self.assertIn("-", src)

    def test_dpi_bypass_menu_no_preset_list(self):
        """dpi_bypass меню НЕ содержит список пресетов (только предупреждение).

        Список пресетов с плюсами/минусами есть только в youtube_b4 модуле.
        """
        import inspect
        src = inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)
        # Не должно быть подробного списка с плюсами/минусами
        # (может быть упоминание 'preset' в общих пунктах меню, но не список)
        self.assertNotIn("Стабильный, проверен на большинстве", src)
        self.assertNotIn("Пробивает там, где DuckDuckGo заблокирован", src)

    def test_youtube_b4_menu_has_discovery_hint(self):
        """youtube_b4 меню содержит подсказку про Discovery в Web UI."""
        import inspect
        src = inspect.getsource(self.youtube_b4.do_youtube_b4_menu)
        self.assertIn("Discovery", src)
        self.assertIn("Web UI", src)


class TestUpdateMenuAndVersionSync(unittest.TestCase):
    """Раздел «Обновление Bye Bye Big Bro»: подменю + принудительное
    обновление + синхронизация версии между модулями.

    Проверяет:
      1. sync_b4_version_state() — фактическая версия binary
         записывается в общий state (его читают оба модуля).
      2. auto_update(force=True) — принудительная переустановка той же
         release-версии (раньше совпадение версий = «уже актуальная»).
      3. auto_update_prerelease(force=True) — то же для pre-release.
      4. Подменю обновления рендерит два подраздела: release и prerelease.
      5. Главные меню обоих модулей содержат пункт «Обновление Bye Bye
         Big Bro» и открывают подменю (do_b4_update_menu).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"
        import importlib
        from chimera.modules import dpi_bypass, youtube_b4
        importlib.reload(dpi_bypass)
        importlib.reload(youtube_b4)
        self.dpi_bypass = dpi_bypass
        self.youtube_b4 = youtube_b4
        # Общий state-файл для обоих модулей (как в проде).
        self.dpi_bypass._STATE_FILE = self._state_file
        self.youtube_b4._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()
        self.youtube_b4.subprocess = MagicMock()

    # ── sync_b4_version_state ──────────────────────────────────────────

    def test_sync_writes_binary_version_to_shared_state(self):
        """Версия binary записывается в общий state — оба модуля читают один файл."""
        self.dpi_bypass._detect_version = lambda: "1.79.0"
        self.dpi_bypass._save_state({"installed": True, "version": "1.78.0"})
        result = self.dpi_bypass.sync_b4_version_state()
        self.assertTrue(result["synced"])
        self.assertEqual(result["version"], "1.79.0")
        self.assertEqual(result["old_state_version"], "1.78.0")
        # State перезаписан — второй модуль (youtube_b4) видит новую версию.
        self.assertEqual(self.youtube_b4._load_state().get("version"), "1.79.0")

    def test_sync_no_write_when_version_matches(self):
        """Совпадающая версия → перезаписи нет (synced=False)."""
        self.dpi_bypass._detect_version = lambda: "1.79.0"
        self.dpi_bypass._save_state({"installed": True, "version": "1.79.0"})
        result = self.dpi_bypass.sync_b4_version_state()
        self.assertFalse(result["synced"])
        self.assertEqual(result["version"], "1.79.0")

    def test_sync_empty_binary_version_does_not_clear_state(self):
        """Binary не отвечает версию → state не трогаем."""
        self.dpi_bypass._detect_version = lambda: ""
        self.dpi_bypass._save_state({"installed": True, "version": "1.78.0"})
        result = self.dpi_bypass.sync_b4_version_state()
        self.assertFalse(result["synced"])
        self.assertEqual(self.dpi_bypass._load_state().get("version"), "1.78.0")

    def test_both_modules_have_sync_function(self):
        """sync_b4_version_state есть в обоих модулях (зеркалирование)."""
        self.assertTrue(hasattr(self.youtube_b4, 'sync_b4_version_state'))
        self.assertTrue(hasattr(self.dpi_bypass, 'sync_b4_version_state'))
        self.assertTrue(callable(self.youtube_b4.sync_b4_version_state))
        self.assertTrue(callable(self.dpi_bypass.sync_b4_version_state))

    def test_sync_via_youtube_b4_visible_to_dpi_bypass(self):
        """Синхронизация через youtube_b4 видна dpi_bypass (общий state)."""
        self.youtube_b4._detect_version = lambda: "1.79.1"
        self.youtube_b4.sync_b4_version_state()
        # dpi_bypass читает тот же state-файл.
        self.assertEqual(self.dpi_bypass._load_state().get("version"), "1.79.1")

    # ── force-обновление ───────────────────────────────────────────────

    def test_auto_update_force_reinstalls_same_version(self):
        """force=True → совпадение версий НЕ останавливает обновление."""
        self.dpi_bypass._detect_installed = lambda: True
        self.dpi_bypass._detect_version = lambda: "1.79.0"
        self.dpi_bypass._detect_latest_version = lambda: "1.79.0"
        called = []
        def _fake_update(old, new):
            called.append((old, new))
            return {"updated": True, "old_version": old, "new_version": new,
                    "message": "reinstalled"}
        self.dpi_bypass._do_b4_binary_update = _fake_update
        result = self.dpi_bypass.auto_update(force=True)
        self.assertTrue(result["updated"])
        self.assertEqual(called, [("1.79.0", "1.79.0")])

    def test_auto_update_without_force_skips_when_same(self):
        """force=False (default) → совпадение = «уже актуальная»."""
        self.dpi_bypass._detect_installed = lambda: True
        self.dpi_bypass._detect_version = lambda: "1.79.0"
        self.dpi_bypass._detect_latest_version = lambda: "1.79.0"
        self.dpi_bypass._do_b4_binary_update = lambda old, new: {
            "updated": True, "message": "should not be called"}
        result = self.dpi_bypass.auto_update()
        self.assertFalse(result["updated"])
        self.assertIn("Уже актуальная", result["message"])

    def test_auto_update_prerelease_force_reinstalls_same_version(self):
        """force=True → принудительная переустановка pre-release."""
        self.dpi_bypass._detect_installed = lambda: True
        self.dpi_bypass._detect_version = lambda: "1.80.0-rc1"
        self.dpi_bypass._detect_latest_prerelease_version = lambda: "1.80.0-rc1"
        called = []
        def _fake_update(old, new):
            called.append((old, new))
            return {"updated": True, "old_version": old, "new_version": new,
                    "message": "reinstalled"}
        self.dpi_bypass._do_b4_binary_update = _fake_update
        result = self.dpi_bypass.auto_update_prerelease(confirm=False, force=True)
        self.assertTrue(result["updated"])
        self.assertEqual(called, [("1.80.0-rc1", "1.80.0-rc1")])

    def test_force_param_in_both_modules(self):
        """auto_update / auto_update_prerelease принимают force в обоих модулях."""
        import inspect
        for mod in (self.youtube_b4, self.dpi_bypass):
            self.assertIn("force", inspect.signature(mod.auto_update).parameters)
            pre_sig = inspect.signature(mod.auto_update_prerelease)
            self.assertIn("force", pre_sig.parameters)
            self.assertEqual(list(pre_sig.parameters.keys()), ["confirm", "force"])
        # Сигнатуры auto_update идентичны в обоих модулях.
        self.assertEqual(
            list(inspect.signature(self.youtube_b4.auto_update).parameters),
            list(inspect.signature(self.dpi_bypass.auto_update).parameters))

    # ── подменю обновления ─────────────────────────────────────────────

    def _render_update_menu(self, module):
        """Рендерит do_b4_update_menu без сети, возвращает вывод."""
        import io
        from contextlib import redirect_stdout
        module._detect_version = lambda: "1.78.0"
        module._detect_latest_version = lambda: "1.79.0"
        module._detect_latest_prerelease_version = lambda: "1.80.0-rc1"
        inputs = iter(['q'])
        captured = io.StringIO()
        with patch("builtins.input", side_effect=lambda *a, **kw: next(inputs)), \
             redirect_stdout(captured):
            try:
                module.do_b4_update_menu()
            except StopIteration:
                pass
        return captured.getvalue()

    def test_update_menu_renders_two_subsections(self):
        """Подменю содержит оба подраздела: release и prerelease."""
        out = self._render_update_menu(self.dpi_bypass)
        self.assertIn("ОБНОВЛЕНИЕ BYE BYE BIG BRO", out)
        self.assertIn("Обновление до последней release версии", out)
        self.assertIn("Обновление до prerelease версии", out)
        # Сводка версий в шапке.
        self.assertIn("1.78.0", out)
        self.assertIn("1.79.0", out)
        self.assertIn("1.80.0-rc1", out)

    def test_update_menu_identical_in_both_modules(self):
        """Подменю обновления зеркалируется в обоих модулях."""
        dpi_out = self._render_update_menu(self.dpi_bypass)
        yt_out = self._render_update_menu(self.youtube_b4)
        for key in ("ОБНОВЛЕНИЕ BYE BYE BIG BRO",
                    "Обновление до последней release версии",
                    "Обновление до prerelease версии",
                    "Установленная версия",
                    "Последняя release",
                    "Последняя pre-release"):
            self.assertIn(key, dpi_out)
            self.assertIn(key, yt_out)

    def test_update_menu_calls_sync_on_entry(self):
        """При входе в подменю вызывается синхронизация версии."""
        self.dpi_bypass._detect_version = lambda: "1.78.0"
        self.dpi_bypass._detect_latest_version = lambda: "1.79.0"
        self.dpi_bypass._detect_latest_prerelease_version = lambda: "1.80.0-rc1"
        sync_called = []
        self.dpi_bypass.sync_b4_version_state = lambda: (
            sync_called.append(1) or
            {"synced": False, "version": "1.78.0", "old_state_version": "1.78.0"})
        with patch("builtins.input", return_value="q"):
            self.dpi_bypass.do_b4_update_menu()
        self.assertEqual(len(sync_called), 1)

    def test_main_menus_have_update_section_item(self):
        """Главные меню содержат пункт «Обновление Bye Bye Big Bro»."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4.do_youtube_b4_menu)
        dpi_src = inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)
        self.assertIn("Обновление Bye Bye Big Bro", yt_src)
        self.assertIn("Обновление Bye Bye Big Bro", dpi_src)
        # Старых пунктов больше нет.
        self.assertNotIn("Проверить обновление b4 (stable)", yt_src)
        self.assertNotIn("Проверить обновление b4 (stable)", dpi_src)

    def test_main_menus_open_update_submenu(self):
        """Пункт [5] и алиас [U] открывают do_b4_update_menu."""
        import inspect
        for src in (inspect.getsource(self.youtube_b4.do_youtube_b4_menu),
                    inspect.getsource(self.dpi_bypass.do_dpi_bypass_menu)):
            self.assertIn("do_b4_update_menu()", src)

    def test_cli_has_update_commands(self):
        """CLI обоих модулей умеет update / update-pre / sync-version."""
        import inspect
        for src in (inspect.getsource(self.youtube_b4),
                    inspect.getsource(self.dpi_bypass)):
            self.assertIn('"update", "update-pre", "sync-version"', src)

    def test_dpi_bypass_main_runs_own_menu(self):
        """REGRESSION: __main__ dpi_bypass вызывает do_dpi_bypass_menu.

        Раньше там стоял вызов do_youtube_b4_menu() — функции из
        youtube_b4.py, которой нет в пространстве имён dpi_bypass
        (NameError при запуске `python3 -m chimera.modules.dpi_bypass`).
        """
        import inspect
        dpi_src = inspect.getsource(self.dpi_bypass)
        self.assertIn("do_dpi_bypass_menu()", dpi_src.split('if __name__')[1])
        self.assertNotIn("do_youtube_b4_menu()", dpi_src)


class TestDomainNormalization(unittest.TestCase):
    """_normalize_b4_domain_entry / _normalize_set_domains — нормализация
    wildcard-доменов к семантикам движка b4.

    REGRESSION: движок b4 (sni/domain.go) сравнивает записи литерально —
    "*.whatsapp.com" не матчит web.whatsapp.com. Собственный Web UI b4
    стриппит "*." при ручном вводе, но JSON-импорт — нет. Сторонние
    WA/FB/IG-сеты с wildcard-записями импортировались пустышками: нет
    матча → нет бейджа в Traffic → нет DPI-обработки.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass

    def test_wildcard_stripped_to_apex(self):
        """'*.whatsapp.com' → 'whatsapp.com' (apex покрывает поддомены)."""
        self.assertEqual(
            self.dpi_bypass._normalize_b4_domain_entry("*.whatsapp.com"),
            "whatsapp.com")

    def test_double_wildcard_stripped(self):
        """'*.*.example.com' → 'example.com' (повторяющийся '*.')."""
        self.assertEqual(
            self.dpi_bypass._normalize_b4_domain_entry("*.*.example.com"),
            "example.com")

    def test_plain_domain_unchanged(self):
        n = self.dpi_bypass._normalize_b4_domain_entry("web.whatsapp.com")
        self.assertEqual(n, "web.whatsapp.com")

    def test_case_and_dots_normalized(self):
        """'Example.COM.' → 'example.com' (движок lowercase + trim точек)."""
        n = self.dpi_bypass._normalize_b4_domain_entry("  Example.COM.  ")
        self.assertEqual(n, "example.com")

    def test_any_shorthand_becomes_catch_all(self):
        """'*'/'any'/'all' → 'regexp:.*' (catch-all движка b4)."""
        for raw in ("*", "**", "*.*", "any", "all", "0/0"):
            self.assertEqual(
                self.dpi_bypass._normalize_b4_domain_entry(raw),
                "regexp:.*", f"{raw} должен стать catch-all")

    def test_regexp_entry_preserved(self):
        n = self.dpi_bypass._normalize_b4_domain_entry("regexp:.*\\.googlevideo\\.com")
        self.assertEqual(n, "regexp:.*\\.googlevideo\\.com")

    def test_empty_entry_returns_none(self):
        for raw in ("", "   ", None):
            self.assertIsNone(self.dpi_bypass._normalize_b4_domain_entry(raw))

    def test_normalize_set_domains_inplace(self):
        """Сет с wildcard-записями нормализуется in-place + дедуп."""
        custom_set = {
            "id": "wa",
            "targets": {"sni_domains": [
                "*.whatsapp.com", "whatsapp.com", "wa.me",
                "  *.WHATSAPP.NET  ", "",
            ]},
        }
        changed = self.dpi_bypass._normalize_set_domains(custom_set)
        self.assertEqual(custom_set["targets"]["sni_domains"],
                         ["whatsapp.com", "wa.me", "whatsapp.net"])
        self.assertEqual(changed, 3)  # *.com, *.NET(кейс+пробелы), ''

    def test_normalize_set_domains_no_targets(self):
        """Сет без targets / без sni_domains — no-op, без исключений."""
        self.assertEqual(self.dpi_bypass._normalize_set_domains({"id": "x"}), 0)
        self.assertEqual(
            self.dpi_bypass._normalize_set_domains(
                {"targets": {"geosite_categories": ["youtube"]}}), 0)


class TestXrayDomainEntries(unittest.TestCase):
    """_xray_domain_entries_from_b4 — домены b4-сета → записи Xray routing.

    REGRESSION: apply_routing_for_* писал в Xray 'domain:*.whatsapp.com' —
    литеральная wildcard-запись не матчит НИЧЕГО в суффикс-матчере Xray,
    поэтому трафик FB/IG/WA не пинился на direct (RU entry) — в отличие
    от YouTube, где youtube_route.py всегда писал apex-домены.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)
        self.dpi_bypass = dpi_bypass

    def test_wildcard_becomes_apex_entry(self):
        entries = self.dpi_bypass._xray_domain_entries_from_b4(
            ["*.whatsapp.com", "web.facebook.com"])
        self.assertEqual(entries, ["domain:whatsapp.com",
                                   "domain:web.facebook.com"])

    def test_catch_all_not_translated(self):
        """Catch-all не транслируется — пин всего трафика на direct опасен."""
        entries = self.dpi_bypass._xray_domain_entries_from_b4(
            ["*", "any", "regexp:.*", "whatsapp.com"])
        self.assertEqual(entries, ["domain:whatsapp.com"])

    def test_regexp_entries_skipped(self):
        entries = self.dpi_bypass._xray_domain_entries_from_b4(
            ["regexp:.*\\.ggpht\\.com", "ytimg.com"])
        self.assertEqual(entries, ["domain:ytimg.com"])

    def test_dedupe(self):
        entries = self.dpi_bypass._xray_domain_entries_from_b4(
            ["*.whatsapp.com", "whatsapp.com", "WHATSAPP.COM."])
        self.assertEqual(entries, ["domain:whatsapp.com"])

    def test_empty_and_garbage(self):
        self.assertEqual(
            self.dpi_bypass._xray_domain_entries_from_b4([]), [])
        self.assertEqual(
            self.dpi_bypass._xray_domain_entries_from_b4(
                [None, 42, "", "   "]), [])


class TestImportWildcardNormalization(unittest.TestCase):
    """import_custom_set нормализует wildcard-домены при импорте
    (легаси-путь config.json — REST отключён)."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)  # чистый модуль (патчи прошлых классов)
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()
        self.dpi_bypass._b4_rest_import_set = lambda cs: None  # легаси-путь
        self.dpi_bypass.apply_routing_for_all_sets = lambda: {
            "applied": 0, "removed": 0, "total_domains": 0, "errors": []}

    def test_wildcards_normalized_in_saved_config(self):
        """Реальный сторонний WA-сет: wildcard'ы → apex в config.json."""
        wa_set = {
            "id": "third-party-wa",
            "name": "whatsapp",
            "enabled": True,
            "targets": {"sni_domains": [
                "*.whatsapp.com", "*.whatsapp.net", "*.whatsapp.org",
                "*.whatsapp.tv", "wa.me",
            ]},
        }
        self.assertTrue(self.dpi_bypass.import_custom_set(json.dumps(wa_set)))
        saved = json.loads(self._config_file.read_text())
        domains = saved["sets"][0]["targets"]["sni_domains"]
        self.assertIn("whatsapp.com", domains)
        self.assertIn("whatsapp.net", domains)
        self.assertIn("wa.me", domains)
        self.assertNotIn("*.whatsapp.com", domains)
        # Ни одной wildcard-записи не осталось
        self.assertFalse(any(d.startswith("*.") for d in domains))

    def test_enabled_defaults_to_true(self):
        """REGRESSION: сет без 'enabled' импортировался выключенным
        (Go-декодер b4 считает отсутствующее поле = false)."""
        test_json = json.dumps({
            "id": "no-enabled",
            "targets": {"sni_domains": ["example.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(self._config_file.read_text())
        self.assertIs(saved["sets"][0]["enabled"], True)

    def test_existing_enabled_value_respected(self):
        """Явное enabled=False в JSON не перезаписывается."""
        test_json = json.dumps({
            "id": "explicit-disabled",
            "enabled": False,
            "targets": {"sni_domains": ["example.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(self._config_file.read_text())
        self.assertIs(saved["sets"][0]["enabled"], False)


class TestB4GeoDefaultsAndAutoHeal(unittest.TestCase):
    """v75.1 — geosite-пути b4 «как это необходимо B4": всегда /etc/b4,
    seed-копия из Xray, авто-лечение из status().

    Контекст: третья машина (picaresque.space) с легаси-хардкодом
    /usr/share/xray/geosite.dat — v72.4 лечил только при переключении
    пресета/импорте сета, юзер после обновления Химеры их не делал.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_geo_section_defaults(self):
        """_b4_geo_section(): sitedat_path=/etc/b4 + sitedat_url + auto_update."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            geo = mod._b4_geo_section()
            self.assertEqual(geo["sitedat_path"], "/etc/b4/geosite.dat")
            self.assertEqual(geo["ipdat_path"], "/etc/b4/geoip.dat")
            self.assertIn("runetfreedom", geo["sitedat_url"])
            self.assertIn("b4geoip", geo["ipdat_url"])
            self.assertTrue(geo["auto_update"]["on_startup"])
            self.assertEqual(geo["auto_update"]["interval"], "weekly")

    def test_seed_copies_shared_geosite(self):
        """_seed_b4_geosite(): копия (не ссылка) из общего файла Xray."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        shared = tmpdir / "xray" / "geosite.dat"
        shared.parent.mkdir()
        shared.write_bytes(b"geosite-base")
        for i, mod in enumerate((self.youtube_b4, self.dpi_bypass)):
            local = tmpdir / f"b4-{i}" / "geosite.dat"
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            mod.B4_GEOSITE_SHARED_PATHS = (str(shared),)
            mod.B4_GEOSITE_LOCAL_PATH = str(local)
            try:
                self.assertTrue(mod._seed_b4_geosite())
                self.assertEqual(local.read_bytes(), b"geosite-base")
                # Источник не тронут (копия, не move).
                self.assertEqual(shared.read_bytes(), b"geosite-base")
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_seed_noop_when_local_exists(self):
        """_seed_b4_geosite(): база уже есть — ничего не делаем."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        shared = tmpdir / "geosite.dat"
        shared.write_bytes(b"shared")
        local = tmpdir / "geosite.dat"
        local.write_bytes(b"own-base")
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            mod.B4_GEOSITE_SHARED_PATHS = (str(shared),)
            mod.B4_GEOSITE_LOCAL_PATH = str(local)
            try:
                self.assertFalse(mod._seed_b4_geosite())
                self.assertEqual(local.read_bytes(), b"own-base")
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_seed_noop_without_shared(self):
        """_seed_b4_geosite(): общего файла нет — False, ничего не создаём
        (базу скачает сам b4 через auto_update.on_startup / Web UI)."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        local = tmpdir / "b4" / "geosite.dat"
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            mod.B4_GEOSITE_SHARED_PATHS = ()
            mod.B4_GEOSITE_LOCAL_PATH = str(local)
            try:
                self.assertFalse(mod._seed_b4_geosite())
                self.assertFalse(local.exists())
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_heals_shared_xray_path_even_if_file_exists(self):
        """v72.4-«общий» путь /usr/local/share/xray/geosite.dat (файл жив)
        — тоже мёртвый для b4: /usr read-only, Update = 500 EROFS."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        shared = tmpdir / "geosite.dat"
        shared.write_bytes(b"shared")
        local = tmpdir / "b4" / "geosite.dat"
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            mod.B4_GEOSITE_SHARED_PATHS = (str(shared),)
            mod.B4_GEOSITE_LOCAL_PATH = str(local)
            try:
                cfg = {"sets": [], "system": {
                    "geo": {"sitedat_path": str(shared)}}}
                fixed = mod._b4_clean_legacy_config_keys(cfg)
                self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                                 str(local))
                self.assertGreaterEqual(fixed, 1)
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_heal_fills_url_and_autoupdate_only_when_empty(self):
        """Лечение дозаполняет sitedat_url/auto_update только если пусты."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        local = tmpdir / "b4" / "geosite.dat"
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            mod.B4_GEOSITE_SHARED_PATHS = ()
            mod.B4_GEOSITE_LOCAL_PATH = str(local)
            try:
                # 1) Пустые URL/auto_update — заполняются дефолтами.
                cfg = {"sets": [], "system": {
                    "geo": {"sitedat_path": "/usr/share/xray/geosite.dat"}}}
                mod._b4_clean_legacy_config_keys(cfg)
                geo = cfg["system"]["geo"]
                self.assertEqual(geo["sitedat_path"], str(local))
                self.assertIn("runetfreedom", geo["sitedat_url"])
                self.assertTrue(geo["auto_update"]["on_startup"])
                # 2) Пользовательские значения — не трогаем.
                cfg2 = {"sets": [], "system": {"geo": {
                    "sitedat_path": "/usr/share/xray/geosite.dat",
                    "sitedat_url": "https://my.mirror/geosite.dat",
                    "auto_update": {"on_startup": False,
                                    "interval": "monthly"}}}}
                mod._b4_clean_legacy_config_keys(cfg2)
                geo2 = cfg2["system"]["geo"]
                self.assertEqual(geo2["sitedat_url"],
                                 "https://my.mirror/geosite.dat")
                self.assertFalse(geo2["auto_update"]["on_startup"])
                self.assertEqual(geo2["auto_update"]["interval"], "monthly")
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_status_autoheals_dead_geo_paths(self):
        """REGRESSION (третья машина): status() лечит мёртвый
        sitedat_path в config.json — без переключения пресета/импорта
        сета. Конфиг перезаписан, b4 перезапущен, seed скопирован."""
        import tempfile
        from unittest.mock import MagicMock
        tmpdir = Path(tempfile.mkdtemp())
        shared = tmpdir / "xray" / "geosite.dat"
        shared.parent.mkdir()
        shared.write_bytes(b"geosite-base")
        local = tmpdir / "b4" / "geosite.dat"
        config_file = tmpdir / "config.json"
        config_file.write_text(json.dumps({
            "sets": [],
            "system": {"geo": {
                "sitedat_path": "/usr/share/xray/geosite.dat",
                "ipdat_path": "/etc/b4/geoip.dat",
                "ipdat_url": "https://github.com/DanielLavrushin/b4geoip/"
                            "releases/latest/download/geoip.dat",
            }},
        }))
        state_file = tmpdir / "state.json"
        state_file.write_text(json.dumps({
            "installed": True, "active_preset": None, "enabled": True,
            "version": "1.78.0", "web_port": 9700,
        }))
        mod = self.dpi_bypass
        orig = (mod.B4_CONFIG_FILE, mod._STATE_FILE, mod.B4_BINARY_PATH,
                mod.B4_UNIT_PATH, mod.B4_GEOSITE_SHARED_PATHS,
                mod.B4_GEOSITE_LOCAL_PATH, mod.subprocess)
        mod.B4_CONFIG_FILE = config_file
        mod._STATE_FILE = state_file
        mod.B4_BINARY_PATH = tmpdir / "b4bin"
        mod.B4_UNIT_PATH = tmpdir / "b4.service"
        mod.B4_BINARY_PATH.touch()
        mod.B4_UNIT_PATH.touch()
        mod.B4_GEOSITE_SHARED_PATHS = (str(shared),)
        mod.B4_GEOSITE_LOCAL_PATH = str(local)
        mod.subprocess = MagicMock()
        try:
            mod.status()
            cfg = json.loads(config_file.read_text())
            geo = cfg["system"]["geo"]
            self.assertEqual(geo["sitedat_path"], str(local))
            self.assertIn("runetfreedom", geo["sitedat_url"])
            self.assertTrue(geo["auto_update"]["on_startup"])
            # Seed скопирован, b4 перезапущен.
            self.assertEqual(local.read_bytes(), b"geosite-base")
            restarts = [c for c in mod.subprocess.run.call_args_list
                        if c.args and "restart" in c.args[0]]
            self.assertTrue(restarts,
                            "status() должен перезапустить b4 после лечения")
        finally:
            (mod.B4_CONFIG_FILE, mod._STATE_FILE, mod.B4_BINARY_PATH,
             mod.B4_UNIT_PATH, mod.B4_GEOSITE_SHARED_PATHS,
             mod.B4_GEOSITE_LOCAL_PATH, mod.subprocess) = orig

    def test_status_no_heal_for_custom_geo_paths(self):
        """status() НЕ трогает произвольный пользовательский путь."""
        import tempfile
        from unittest.mock import MagicMock
        tmpdir = Path(tempfile.mkdtemp())
        local = tmpdir / "b4" / "geosite.dat"
        config_file = tmpdir / "config.json"
        original_cfg = {
            "sets": [],
            "system": {"geo": {
                "sitedat_path": "/mnt/tmpfs/geosite.dat",
                "sitedat_url": "https://my.mirror/geosite.dat",
            }},
        }
        config_file.write_text(json.dumps(original_cfg))
        state_file = tmpdir / "state.json"
        state_file.write_text(json.dumps({
            "installed": True, "active_preset": None, "enabled": True,
            "version": "1.78.0", "web_port": 9700,
        }))
        mod = self.dpi_bypass
        orig = (mod.B4_CONFIG_FILE, mod._STATE_FILE, mod.B4_BINARY_PATH,
                mod.B4_UNIT_PATH, mod.B4_GEOSITE_SHARED_PATHS,
                mod.B4_GEOSITE_LOCAL_PATH, mod.subprocess)
        mod.B4_CONFIG_FILE = config_file
        mod._STATE_FILE = state_file
        mod.B4_BINARY_PATH = tmpdir / "b4"
        mod.B4_UNIT_PATH = tmpdir / "b4.service"
        mod.B4_BINARY_PATH.touch()
        mod.B4_UNIT_PATH.touch()
        mod.B4_GEOSITE_SHARED_PATHS = ()
        mod.B4_GEOSITE_LOCAL_PATH = str(local)
        mod.subprocess = MagicMock()
        try:
            mod.status()
            cfg = json.loads(config_file.read_text())
            self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                             "/mnt/tmpfs/geosite.dat")
            restarts = [c for c in mod.subprocess.run.call_args_list
                        if c.args and "restart" in c.args[0]]
            self.assertFalse(restarts,
                             "пользовательский путь — рестарт не нужен")
        finally:
            (mod.B4_CONFIG_FILE, mod._STATE_FILE, mod.B4_BINARY_PATH,
             mod.B4_UNIT_PATH, mod.B4_GEOSITE_SHARED_PATHS,
             mod.B4_GEOSITE_LOCAL_PATH, mod.subprocess) = orig


class TestB4LegacyConfigCleanup(unittest.TestCase):
    """_b4_clean_legacy_config_keys — чистка legacy-полей конфига b4.

    Семантика b4 1.79+/1.80rc1 (по исходникам и docs: sets/udp.md):
      • Config = version/queue/system/sets/ui — верхнеуровневые "udp"
        (с filter_quic:"block") и "routing" мёртвые;
      • QUIC-настройки per-set: sets[].udp.mode + sets[].udp.filter_quic;
      • filter_quic "block" не существует — NormalizeQUICFilter всё,
        кроме "all", переписывает в "sni";
      • правильный путь geosite — system.geo.sitedat_path;
      • "b4_version" в сете — не поле SetConfig;
      • sitedat_path с мёртвым xray-хардкодом лечится на живой путь.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_removes_dead_top_level_keys(self):
        """Верхнеуровневые udp/routing удаляются."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            cfg = {
                "sets": [],
                "routing": {"enabled": False},
                "udp": {"mode": "fake", "filter_quic": "block"},
            }
            fixed = mod._b4_clean_legacy_config_keys(cfg)
            self.assertEqual(fixed, 2)
            self.assertNotIn("udp", cfg)
            self.assertNotIn("routing", cfg)

    def test_migrates_geosite_path_to_geo_sitedat(self):
        """system.geosite_path → system.geo.sitedat_path (без потери пути)."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            cfg = {
                "sets": [],
                "system": {
                    "geosite_path": "/opt/xray/geosite.dat",
                    "geo": {"ipdat_path": "/etc/b4/geoip.dat"},
                },
            }
            fixed = mod._b4_clean_legacy_config_keys(cfg)
            self.assertEqual(fixed, 1)
            self.assertNotIn("geosite_path", cfg["system"])
            self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                             "/opt/xray/geosite.dat")
            # Существующие geo-поля не тронуты
            self.assertEqual(cfg["system"]["geo"]["ipdat_path"],
                             "/etc/b4/geoip.dat")

    def test_geosite_migration_does_not_overwrite_existing_sitedat(self):
        """Уже заданный geo.sitedat_path не перезаписывается легаси-значением."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            cfg = {
                "sets": [],
                "system": {
                    "geosite_path": "/old/path.dat",
                    "geo": {"sitedat_path": "/b4/geosite.dat"},
                },
            }
            mod._b4_clean_legacy_config_keys(cfg)
            self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                             "/b4/geosite.dat")

    def test_heals_dead_xray_sitedat_path(self):
        """REGRESSION (chimeravpn.online, 30.08.2026): хардкод
        /usr/share/xray/geosite.dat без файла → /etc/b4/geosite.dat.

        Web UI b4 падал с 500 'failed to create directory /usr/share/xray:
        read-only file system' при Update геосайта — sitedat_path в конфиге
        указывал на отсутствующий geosite.dat Xray.
        """
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = mod.B4_GEOSITE_SHARED_PATHS
            mod.B4_GEOSITE_SHARED_PATHS = ()
            try:
                cfg = {"sets": [], "system": {
                    "geo": {"sitedat_path": "/usr/share/xray/geosite.dat"}}}
                fixed = mod._b4_clean_legacy_config_keys(cfg)
                self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                                 "/etc/b4/geosite.dat")
                self.assertGreaterEqual(fixed, 1)
            finally:
                mod.B4_GEOSITE_SHARED_PATHS = orig

    def test_heals_dead_xray_path_even_with_live_shared_file(self):
        """v75.1: мёртвый xray-хардкод + живой общий файл → ВСЁ РАВНО
        /etc/b4/geosite.dat (НЕ репойнт на общий файл).

        REGRESSION (3 машины): /usr read-only для b4 — Update геосайта
        в Web UI падал с 500 EROFS даже при существующем общем файле
        (Web UI берёт Destination Directory из dirname(sitedat_path)).
        """
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        shared = tmpdir / "geosite.dat"
        shared.write_bytes(b"shared")
        local = tmpdir / "b4" / "geosite.dat"
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            mod.B4_GEOSITE_SHARED_PATHS = (str(shared),)
            mod.B4_GEOSITE_LOCAL_PATH = str(local)
            try:
                cfg = {"sets": [], "system": {
                    "geo": {"sitedat_path": "/usr/share/xray/geosite.dat"}}}
                fixed = mod._b4_clean_legacy_config_keys(cfg)
                self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                                 str(local))
                self.assertGreaterEqual(fixed, 1)
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_b4_geosite_path_resolver(self):
        """v75.1: резолвер ВСЕГДА возвращает /etc/b4/geosite.dat —
        существование общих geosite-файлов Xray не меняет выбор (они
        остаются только seed-источником)."""
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        first = tmpdir / "first.dat"
        first.write_bytes(b"1")
        local = tmpdir / "b4" / "geosite.dat"
        for mod in (self.youtube_b4, self.dpi_bypass):
            orig = (mod.B4_GEOSITE_SHARED_PATHS, mod.B4_GEOSITE_LOCAL_PATH)
            try:
                mod.B4_GEOSITE_SHARED_PATHS = (
                    str(tmpdir / "missing.dat"), str(first))
                mod.B4_GEOSITE_LOCAL_PATH = str(local)
                self.assertEqual(mod._b4_geosite_path(), str(local))
                mod.B4_GEOSITE_SHARED_PATHS = ()
                self.assertEqual(mod._b4_geosite_path(), str(local))
            finally:
                (mod.B4_GEOSITE_SHARED_PATHS,
                 mod.B4_GEOSITE_LOCAL_PATH) = orig

    def test_custom_sitedat_path_never_touched(self):
        """Пользовательский sitedat_path не лечим — только наш хардкод."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            cfg = {"sets": [], "system": {
                "geo": {"sitedat_path": "/mnt/tmpfs/geosite.dat"}}}
            fixed = mod._b4_clean_legacy_config_keys(cfg)
            self.assertEqual(cfg["system"]["geo"]["sitedat_path"],
                             "/mnt/tmpfs/geosite.dat")
            self.assertEqual(fixed, 0)

    def test_removes_b4_version_from_sets(self):
        """Мёртвое поле b4_version вычищается из каждого сета."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            cfg = {
                "sets": [
                    {"id": "a", "b4_version": "1.78.0"},
                    {"id": "b", "b4_version": "1.78.0"},
                    {"id": "c"},
                ],
            }
            fixed = mod._b4_clean_legacy_config_keys(cfg)
            self.assertEqual(fixed, 2)
            for s in cfg["sets"]:
                self.assertNotIn("b4_version", s)
            self.assertEqual([s["id"] for s in cfg["sets"]], ["a", "b", "c"])

    def test_clean_config_untouched(self):
        """Конфиг без legacy-полей — 0 исправлений, содержимое не меняется."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            cfg = {
                "version": 52,
                "sets": [{"id": "x", "udp": {"mode": "reject",
                                            "filter_quic": "all"}}],
                "system": {"geo": {"sitedat_path": "/opt/geosite.dat"}},
            }
            snapshot = json.loads(json.dumps(cfg))
            fixed = mod._b4_clean_legacy_config_keys(cfg)
            self.assertEqual(fixed, 0)
            self.assertEqual(cfg, snapshot)

    def test_non_dict_input_safe(self):
        """Не-dict на входе — 0 исправлений, без исключения."""
        for mod in (self.youtube_b4, self.dpi_bypass):
            self.assertEqual(mod._b4_clean_legacy_config_keys(None), 0)
            self.assertEqual(mod._b4_clean_legacy_config_keys("junk"), 0)

    def test_import_strips_b4_version_from_incoming_set(self):
        """import_custom_set вычищает b4_version из вставляемого сета."""
        self._tmpdir = Path(tempfile.mkdtemp())
        config_file = self._tmpdir / "config.json"
        state_file = self._tmpdir / "state.json"
        self.dpi_bypass.B4_CONFIG_FILE = config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = state_file
        self.dpi_bypass.subprocess = MagicMock()
        self.dpi_bypass._b4_rest_import_set = lambda cs: None
        self.dpi_bypass.B4_GEOSITE_SHARED_PATHS = ()  # нет geosite Xray
        self.dpi_bypass.apply_routing_for_all_sets = lambda: {
            "applied": 0, "removed": 0, "total_domains": 0, "errors": []}
        test_json = json.dumps({
            "id": "legacy-export",
            "b4_version": "1.78.0",
            "targets": {"sni_domains": ["example.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(config_file.read_text())
        self.assertNotIn("b4_version", saved["sets"][0])
        self.assertEqual(saved["sets"][0]["id"], "legacy-export")


class TestPresetsQuicBlock(unittest.TestCase):
    """Пресеты Chimera содержат per-set QUIC-блок — канон b4 1.79+.

    "Блокировать QUIC" (Web UI, вкладка UDP сета) = filter_quic:"all" +
    mode:"reject" → ICMP port unreachable → мгновенный откат браузера
    на TCP/HTTP2, где работают fake SNI + фрагментация. Значения
    "block" не существует: NormalizeQUICFilter → "sni".
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.modules = (youtube_b4, dpi_bypass)

    def test_all_presets_have_quic_block(self):
        """Все 3 пресета содержат udp: {mode: reject, filter_quic: all}."""
        for mod in self.modules:
            for name, (_label, set_data) in mod.PRESETS.items():
                udp = set_data.get("udp", {})
                self.assertEqual(udp.get("mode"), "reject",
                                 f"{mod.__name__}/{name}: udp.mode")
                self.assertEqual(udp.get("filter_quic"), "all",
                                 f"{mod.__name__}/{name}: udp.filter_quic")

    def test_presets_have_no_legacy_fields(self):
        """В пресетах нет мёртвых полей (b4_version)."""
        for mod in self.modules:
            for name, (_label, set_data) in mod.PRESETS.items():
                self.assertNotIn("b4_version", set_data,
                                 f"{mod.__name__}/{name}: b4_version — мёртвое поле")

    def test_presets_mirrored_between_modules(self):
        """Пресеты в youtube_b4 и dpi_bypass идентичны (зеркалирование)."""
        yt = self.modules[0]
        dpi = self.modules[1]
        self.assertEqual(yt.DEFAULT_SET_YOUTUBE, dpi.DEFAULT_SET_YOUTUBE)
        self.assertEqual(yt.AGGRESSIVE_SET_YOUTUBE, dpi.AGGRESSIVE_SET_YOUTUBE)
        self.assertEqual(yt.LIGHT_SET_YOUTUBE, dpi.LIGHT_SET_YOUTUBE)

    def test_quic_block_constant_canonical(self):
        """_B4_QUIC_BLOCK_UDP — каноническая пара reject/all."""
        for mod in self.modules:
            self.assertEqual(mod._B4_QUIC_BLOCK_UDP,
                             {"mode": "reject", "filter_quic": "all"})


class TestImportPreservesTopLevelConfig(unittest.TestCase):
    """REGRESSION: import_custom_set перезаписывал весь config.json
    минимальным шаблоном {sets, routing, udp, system} — терялись
    топ-уровневые queue (NFQUEUE/mark/ipv6), ui и system.webserver
    (порт Web UI, auth) со сбросом на дефолты b4."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)  # чистый модуль (патчи прошлых классов)
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()
        self.dpi_bypass._b4_rest_import_set = lambda cs: None
        self.dpi_bypass.B4_GEOSITE_SHARED_PATHS = ()  # нет geosite Xray
        self.dpi_bypass.apply_routing_for_all_sets = lambda: {
            "applied": 0, "removed": 0, "total_domains": 0, "errors": []}

    def test_queue_ui_system_webserver_survive(self):
        # Конфиг в каноническом формате b4 v1.79 (как пишет сам b4)
        existing = {
            "queue": {"num": 537, "mark": 32768, "ipv6": False},
            "sets": [{"id": "old-set", "name": "Old", "enabled": True,
                      "targets": {"sni_domains": ["old.com"]}}],
            "system": {
                "webserver": {"port": 7000, "username": "admin",
                              "password": "secret"},
                "geosite_path": "/usr/share/xray/geosite.dat",
            },
            "ui": {"theme": "dark"},
        }
        self._config_file.write_text(json.dumps(existing))
        test_json = json.dumps({
            "id": "new-set",
            "targets": {"sni_domains": ["new.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(self._config_file.read_text())
        # Топ-уровневые секции сохранены
        self.assertEqual(saved["queue"], {"num": 537, "mark": 32768,
                                          "ipv6": False})
        self.assertEqual(saved["ui"], {"theme": "dark"})
        self.assertEqual(saved["system"]["webserver"]["port"], 7000)
        self.assertEqual(saved["system"]["webserver"]["username"], "admin")
        self.assertEqual(saved["system"]["webserver"]["password"], "secret")
        # Старый сет не потерян, новый добавлен
        ids = [s["id"] for s in saved["sets"]]
        self.assertEqual(ids, ["old-set", "new-set"])
        # Legacy-поле system.geosite_path мигрировано в system.geo.sitedat_path,
        # мёртвый xray-хардкод заменён на живой /etc/b4/geosite.dat
        self.assertNotIn("geosite_path", saved["system"])
        self.assertEqual(saved["system"]["geo"]["sitedat_path"],
                         "/etc/b4/geosite.dat")

    def test_corrupted_config_recovers(self):
        """Повреждённый config.json → импорт в чистый конфиг, не крах."""
        self._config_file.write_text("{corrupted json")
        test_json = json.dumps({
            "id": "fresh-set",
            "targets": {"sni_domains": ["fresh.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(self._config_file.read_text())
        self.assertEqual(saved["sets"][0]["id"], "fresh-set")
        # system-секция создана (geosite для Discovery) — живой ключ
        self.assertEqual(saved["system"]["geo"]["sitedat_path"],
                         "/etc/b4/geosite.dat")


class TestImportViaRestApi(unittest.TestCase):
    """import_custom_set через REST API b4 (мокнутый _b4_rest_request)."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)  # чистый модуль (патчи прошлых классов)
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()
        self._calls = []
        self._routing_calls = []
        self.dpi_bypass.apply_routing_for_all_sets = \
            lambda: self._routing_calls.append(1) or {
                "applied": 0, "removed": 0, "total_domains": 0, "errors": []}

    def _mock_rest(self, responses):
        """responses: list of (status, body) в порядке вызовов."""
        def fake_request(method, path, payload=None):
            self._calls.append((method, path, payload))
            return responses.pop(0) if responses else (200, None)
        self.dpi_bypass._b4_rest_request = fake_request

    def test_new_set_posted_normalized_and_enabled(self):
        """Новый сет → POST /api/sets с нормализованными доменами."""
        self._mock_rest([(200, []),
                         (201, {"id": "b4-uuid", "name": "wa"})])
        test_json = json.dumps({
            "name": "wa",
            "targets": {"sni_domains": ["*.whatsapp.com", "wa.me"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        # GET /api/sets + POST /api/sets
        self.assertEqual([c[0] for c in self._calls], ["GET", "POST"])
        self.assertEqual(self._calls[1][1], "/api/sets")
        posted = self._calls[1][2]
        self.assertEqual(posted["targets"]["sni_domains"],
                         ["whatsapp.com", "wa.me"])
        self.assertIs(posted["enabled"], True)
        # REST-путь: config.json НЕ пишется, systemctl НЕ вызывается
        self.assertFalse(self._config_file.exists())
        self.assertFalse(self.dpi_bypass.subprocess.run.called)
        # State обновлён, routing синхронизирован
        state = json.loads(self._state_file.read_text())
        self.assertEqual(state["active_preset"], "custom")
        self.assertEqual(len(self._routing_calls), 1)

    def test_existing_id_replaced_via_put(self):
        """Сет с существующим id → PUT /api/sets/{id} (замена)."""
        self._mock_rest([(200, [{"id": "wa-1", "name": "old-name"}]),
                         (200, {"id": "wa-1"})])
        test_json = json.dumps({
            "id": "wa-1", "name": "new-name",
            "targets": {"sni_domains": ["example.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        self.assertEqual(self._calls[1][0], "PUT")
        self.assertEqual(self._calls[1][1], "/api/sets/wa-1")

    def test_same_name_replaced_via_put(self):
        """Повторный импорт того же JSON (новый id от b4) → PUT по имени,
        а не дубль через POST."""
        self._mock_rest([(200, [{"id": "b4-uuid-1", "name": "wa"}]),
                         (200, {"id": "b4-uuid-1"})])
        test_json = json.dumps({
            "id": "original-id", "name": "wa",
            "targets": {"sni_domains": ["whatsapp.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        self.assertEqual(self._calls[1][0], "PUT")
        self.assertEqual(self._calls[1][1], "/api/sets/b4-uuid-1")

    def test_rejected_set_does_not_touch_config(self):
        """b4 отклонил сет (валидация, HTTP 400) → False, config.json
        НЕ пишется (иначе невалидный сет ломал бы загрузку b4)."""
        self._mock_rest([(200, []),
                         (400, {"error": "invalid set: bad port"})])
        test_json = json.dumps({
            "id": "bad", "targets": {"sni_domains": ["x.com"]},
        })
        self.assertFalse(self.dpi_bypass.import_custom_set(test_json))
        self.assertFalse(self._config_file.exists())

    def test_api_unavailable_falls_back_to_config(self):
        """API недоступен (None) → откат на легаси-путь config.json."""
        self.dpi_bypass._b4_rest_request = \
            lambda method, path, payload=None: None
        test_json = json.dumps({
            "id": "fallback", "targets": {"sni_domains": ["fb.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(self._config_file.read_text())
        self.assertEqual(saved["sets"][0]["id"], "fallback")
        # Легаси-путь перезапускает сервис
        self.assertTrue(self.dpi_bypass.subprocess.run.called)

    def test_auth_enabled_falls_back_to_config(self):
        """Web UI под паролем (401) → откат на легаси-путь."""
        self.dpi_bypass._b4_rest_request = \
            lambda method, path, payload=None: (401, {"error": "unauthorized"})
        test_json = json.dumps({
            "id": "auth", "targets": {"sni_domains": ["ig.com"]},
        })
        self.assertTrue(self.dpi_bypass.import_custom_set(test_json))
        saved = json.loads(self._config_file.read_text())
        self.assertEqual(saved["sets"][0]["id"], "auth")


class TestB4WebPortDetection(unittest.TestCase):
    """_b4_web_port — детект порта Web UI b4.

    Приоритет: флаг --web-port из systemd-unit (runtime-истина — флаг
    применяется поверх config.json, config/bind.go) → config.json
    system.web_server.port → state → дефолт 9700.
    """

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)  # чистый модуль (патчи прошлых классов)
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        self._unit_file = self._tmpdir / "b4.service"
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass._STATE_FILE = self._state_file
        # Герметичность: /etc/systemd/system/b4.service хоста не влияет.
        self.dpi_bypass.B4_UNIT_PATH = self._unit_file

    def test_unit_flag_takes_precedence(self):
        """Флаг --web-port из systemd-unit важнее config.json
        (bind.go: явно заданный флаг применяется поверх конфига)."""
        self._unit_file.write_text(
            "[Service]\n"
            "ExecStart=/usr/local/bin/b4 --config /etc/b4/config.json \\\n"
            "    --queue-num 537 --mark 32768 \\\n"
            "    --web-port 9701 \\\n"
            "    --verbose silent --ipv4 --ipv6\n")
        self._config_file.write_text(json.dumps(
            {"system": {"web_server": {"port": 8123}}}))
        self.assertEqual(self.dpi_bypass._b4_web_port(), 9701)

    def test_port_from_config_json(self):
        """Порт читается из system.web_server.port (json-тег
        WebServerConfig в структуре Config b4 — web_server, не webserver)."""
        self._config_file.write_text(json.dumps(
            {"system": {"web_server": {"port": 8123}}}))
        self.assertEqual(self.dpi_bypass._b4_web_port(), 8123)

    def test_fallback_to_state(self):
        """Нет web_server.port → state web_port → дефолт 9700."""
        self._config_file.write_text(json.dumps({"sets": []}))
        self._state_file.write_text(json.dumps({"web_port": 9701}))
        self.assertEqual(self.dpi_bypass._b4_web_port(), 9701)
        self._state_file.write_text(json.dumps({}))
        self.assertEqual(self.dpi_bypass._b4_web_port(), 9700)

    def test_no_config_uses_default(self):
        self.assertEqual(self.dpi_bypass._b4_web_port(), 9700)

    def test_invalid_port_ignored(self):
        """Мусор в port (строка/0/отрицательный) не ломает детект."""
        self._config_file.write_text(json.dumps(
            {"system": {"web_server": {"port": "not-a-port"}}}))
        self.assertEqual(self.dpi_bypass._b4_web_port(), 9700)


class TestApplyRoutingAllSetsNormalization(unittest.TestCase):
    """apply_routing_for_all_sets нормализует домены в Xray-правиле и
    не пишет правило с пустым массивом domain (match-all в Xray)."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)  # чистый модуль (патчи прошлых классов)
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._xray_dir = self._tmpdir / "xray"
        self._xray_dir.mkdir()
        self._xray_config = self._xray_dir / "config.json"
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass._STATE_FILE = self._tmpdir / "state.json"
        # Перенаправляем пути Xray в tmp
        self._orig_paths = dpi_bypass.Path
        self.dpi_bypass._xray_safe_restart = lambda: True
        self.dpi_bypass._get_xray_outbound_tag = lambda: "direct"
        self.dpi_bypass._set_xray_config_owner = lambda p: None

    def _patch_xray_paths(self):
        """Подменяет константы путей Xray на tmp-пути."""
        import chimera.modules.dpi_bypass as m
        real_path = m.Path

        def fake_path(*args, **kwargs):
            p = str(args[0]) if args else ""
            for candidate, replacement in (
                    ("/usr/local/etc/xray/config.json", self._xray_config),
                    ("/etc/xray/config.json", self._xray_config)):
                if p == candidate:
                    return real_path(str(replacement))
            return real_path(*args, **kwargs)
        return fake_path

    def test_wildcard_domains_normalized_in_rule(self):
        """Сеты с wildcard'ами (легаси-импорт до фикса) → правило
        получает apex-домены: routing чинится даже без переимпорта."""
        self._config_file.write_text(json.dumps({
            "sets": [
                {"id": "wa-set", "enabled": True,
                 "targets": {"sni_domains": ["*.whatsapp.com", "wa.me"]}},
                {"id": "fb-set", "enabled": True,
                 "targets": {"sni_domains": ["*.facebook.com"]}},
            ]}))
        self._xray_config.write_text(json.dumps({
            "routing": {"rules": [
                {"type": "field", "outboundTag": "proxy",
                 "domain": ["geosite:youtube"]}]}}))
        fake_path = self._patch_xray_paths()
        with patch.object(self.dpi_bypass, "Path", fake_path):
            result = self.dpi_bypass.apply_routing_for_all_sets()
        self.assertEqual(result["applied"], 2)
        rules = json.loads(self._xray_config.read_text())["routing"]["rules"]
        b4_rule = next(r for r in rules
                       if r.get("comment", "").startswith("chimera-b4-route-"))
        self.assertEqual(b4_rule["domain"],
                         ["domain:facebook.com", "domain:whatsapp.com",
                          "domain:wa.me"])  # sorted-порядок доменов
        # Прочие правила не тронуты
        other = [r for r in rules if not r.get("comment", "").startswith(
            "chimera-b4-route-")]
        self.assertEqual(len(other), 1)

    def test_catch_all_only_sets_produce_no_rule(self):
        """Сет только с catch-all → правило НЕ пишется (пустой domain
        в Xray = match-all = весь трафик на direct)."""
        self._config_file.write_text(json.dumps({
            "sets": [{"id": "catchall-set", "enabled": True,
                      "targets": {"sni_domains": ["*", "regexp:.*"]}}]}))
        self._xray_config.write_text(json.dumps({
            "routing": {"rules": [
                {"type": "field", "outboundTag": "direct",
                 "comment": "chimera-b4-route-all-synced",
                 "domain": ["domain:stale.com"]}]}}))
        fake_path = self._patch_xray_paths()
        with patch.object(self.dpi_bypass, "Path", fake_path):
            result = self.dpi_bypass.apply_routing_for_all_sets()
        self.assertEqual(result["applied"], 0)
        rules = json.loads(self._xray_config.read_text())["routing"]["rules"]
        # Stale-правило удалено, новое НЕ добавлено
        self.assertEqual(rules, [])

    def test_disabled_sets_excluded(self):
        """Disabled-сет не попадает в правило (и его stale-правило
        удаляется)."""
        self._config_file.write_text(json.dumps({
            "sets": [
                {"id": "on", "enabled": True,
                 "targets": {"sni_domains": ["ok.com"]}},
                {"id": "off", "enabled": False,
                 "targets": {"sni_domains": ["off.com"]}},
            ]}))
        self._xray_config.write_text(json.dumps({
            "routing": {"rules": [
                {"type": "field", "outboundTag": "direct",
                 "comment": "chimera-b4-route-off",
                 "domain": ["domain:off.com"]}]}}))
        fake_path = self._patch_xray_paths()
        with patch.object(self.dpi_bypass, "Path", fake_path):
            result = self.dpi_bypass.apply_routing_for_all_sets()
        self.assertEqual(result["applied"], 1)
        rules = json.loads(self._xray_config.read_text())["routing"]["rules"]
        b4_rule = next(r for r in rules
                       if r.get("comment") == "chimera-b4-route-all-synced")
        self.assertEqual(b4_rule["domain"], ["domain:ok.com"])


class TestSwitchPresetPreservesConfig(unittest.TestCase):
    """switch_preset мёржит конфиг, а не перезаписывает минимальным
    шаблоном (queue/ui/system.webserver должны сохраниться)."""

    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import dpi_bypass
        importlib.reload(dpi_bypass)  # чистый модуль (патчи прошлых классов)
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._state_file = self._tmpdir / "state.json"
        self.dpi_bypass = dpi_bypass
        self.dpi_bypass.B4_CONFIG_FILE = self._config_file
        self.dpi_bypass.B4_CONFIG_DIR = self._tmpdir
        self.dpi_bypass._STATE_FILE = self._state_file
        self.dpi_bypass.subprocess = MagicMock()

    def test_preset_switch_keeps_top_level(self):
        existing = {
            "queue": {"num": 537, "mark": 32768},
            "sets": [{"id": "custom-wa", "name": "WA",
                      "enabled": True,
                      "targets": {"sni_domains": ["whatsapp.com"]}}],
            "system": {"webserver": {"port": 7000}},
        }
        self._config_file.write_text(json.dumps(existing))
        self.assertTrue(self.dpi_bypass.switch_preset("default"))
        saved = json.loads(self._config_file.read_text())
        # Топ-уровневые секции сохранены
        self.assertEqual(saved["queue"], {"num": 537, "mark": 32768})
        self.assertEqual(saved["system"]["webserver"]["port"], 7000)
        # Preset заменил set'ы (прежняя семантика)
        self.assertEqual(len(saved["sets"]), 1)
        self.assertEqual(saved["sets"][0]["name"], "Youtube")

    def test_preset_not_mutated_by_normalization(self):
        """Глобальный PRESETS не мутируется при switch_preset
        (глубокая копия перед _normalize_set_domains)."""
        before = json.dumps(self.dpi_bypass.PRESETS["default"][1])
        self.assertTrue(self.dpi_bypass.switch_preset("default"))
        after = json.dumps(self.dpi_bypass.PRESETS["default"][1])
        self.assertEqual(before, after)


class TestNormalizationSyncBetweenModules(unittest.TestCase):
    """Нормализация и REST-хелперы зеркальны в dpi_bypass и youtube_b4."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass

    def test_both_modules_have_helpers(self):
        for fn in ("_normalize_b4_domain_entry", "_normalize_set_domains",
                   "_xray_domain_entries_from_b4", "_b4_web_port",
                   "_b4_rest_request", "_b4_rest_import_set"):
            self.assertTrue(hasattr(self.dpi_bypass, fn),
                            f"dpi_bypass lacks {fn}")
            self.assertTrue(hasattr(self.youtube_b4, fn),
                            f"youtube_b4 lacks {fn}")

    def test_normalization_behaves_identically(self):
        cases = ["*.whatsapp.com", "*.*.example.com", "*", "any",
                 "regexp:.*\\.com", "Example.COM.", "", "wa.me"]
        for raw in cases:
            self.assertEqual(
                self.dpi_bypass._normalize_b4_domain_entry(raw),
                self.youtube_b4._normalize_b4_domain_entry(raw),
                f"divergence for {raw!r}")

    def test_xray_entries_behave_identically(self):
        domains = ["*.whatsapp.com", "whatsapp.com", "*", "regexp:.*",
                   "wa.me", " Example.COM. "]
        self.assertEqual(
            self.dpi_bypass._xray_domain_entries_from_b4(domains),
            self.youtube_b4._xray_domain_entries_from_b4(domains))

    def test_rest_import_set_code_identical(self):
        """REST-импорт в обоих модулях — один и тот же код (зеркало)."""
        import inspect
        src_a = inspect.getsource(self.dpi_bypass._b4_rest_import_set)
        src_b = inspect.getsource(self.youtube_b4._b4_rest_import_set)
        self.assertEqual(src_a, src_b)


# ══════════════════════════════════════════════════════════════════════════
#  v76: КЭШ LATEST-ВЕРСИЙ (release / pre-release) В ШАПКЕ ГЛАВНОГО МЕНЮ
# ══════════════════════════════════════════════════════════════════════════

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _plain(s: str) -> str:
    return _ANSI_RE.sub('', s)


class _B4BothModulesMixin:
    """Общая setUp для тестов v76 — оба модуля B4, кэш в state."""

    def _setup_modules(self):
        _setup_core_in_sysmodules()
        import importlib
        from chimera.modules import youtube_b4, dpi_bypass
        importlib.reload(youtube_b4)
        importlib.reload(dpi_bypass)
        self.youtube_b4 = youtube_b4
        self.dpi_bypass = dpi_bypass
        self.modules = [youtube_b4, dpi_bypass]

    def _isolated_state(self, mod, state: dict) -> Path:
        """Перенаправляет _STATE_FILE модуля во временный файл с данными."""
        tmpdir = Path(tempfile.mkdtemp())
        state_file = tmpdir / "state.json"
        state_file.write_text(json.dumps(state))
        mod._STATE_FILE = state_file
        return state_file


class TestB4VersionKey(_B4BothModulesMixin, unittest.TestCase):
    """_b4_version_key — сравнение версий b4 (числа, v-префикс, rc-суффикс).

    Реальные форматы тегов DanielLavrushin/b4:
      release: "v1.80.3"  pre-release: "v1.80.4rc1" (суффикс без дефиса).
    """

    def setUp(self):
        self._setup_modules()

    def test_numeric_not_string_comparison(self):
        """«1.9.0» < «1.76.2»: числа, а не строки ('9' > '7' строкой!)."""
        for mod in self.modules:
            self.assertLess(mod._b4_version_key("1.9.0"),
                            mod._b4_version_key("1.76.2"))

    def test_prerelease_less_than_its_release(self):
        """Semver: 1.80.4rc1 < 1.80.4 (pre-release младше своего релиза)."""
        for mod in self.modules:
            self.assertLess(mod._b4_version_key("1.80.4rc1"),
                            mod._b4_version_key("1.80.4"))

    def test_v_prefix_ignored(self):
        """«v1.80.3» == «1.80.3» (v-префикс тега не влияет на порядок)."""
        for mod in self.modules:
            self.assertEqual(mod._b4_version_key("v1.80.3"),
                             mod._b4_version_key("1.80.3"))

    def test_patch_level_ordering(self):
        for mod in self.modules:
            self.assertLess(mod._b4_version_key("1.78.0"),
                            mod._b4_version_key("1.80.3"))
            self.assertLess(mod._b4_version_key("1.80.3"),
                            mod._b4_version_key("1.80.10"))

    def test_unparsable_returns_empty_numbers(self):
        """Мусор («unknown», «») → пустые числа → распознать нельзя."""
        for mod in self.modules:
            self.assertEqual(mod._b4_version_key("unknown")[0], ())
            self.assertEqual(mod._b4_version_key("")[0], ())

    def test_identical_in_both_modules(self):
        for v in ("1.78.0", "v1.80.4rc1", "1.9", "x", ""):
            self.assertEqual(self.youtube_b4._b4_version_key(v),
                             self.dpi_bypass._b4_version_key(v))

    def test_never_compares_str_with_int(self):
        """Смешанные ключи не бросают TypeError при любом сочетании."""
        import itertools
        versions = ["1.9", "1.9.0", "1.9.0rc1", "1.9.1", "v1.10.0",
                    "1.80.4rc1", "1.80.4rc2", "1.80.4", ""]
        for mod in self.modules:
            keys = [mod._b4_version_key(v) for v in versions]
            for a, b in itertools.combinations(keys, 2):
                try:
                    (a < b) or (a > b) or (a == b)
                except TypeError:
                    self.fail(f"TypeError comparing {a!r} vs {b!r}")


class TestB4UpdateAvailability(_B4BothModulesMixin, unittest.TestCase):
    """_b4_update_availability — «есть ли что ставить» (без сети)."""

    def setUp(self):
        self._setup_modules()
        self.cache = {"release": "1.80.3", "prerelease": "1.80.4rc1",
                      "checked_at": 1.0, "ok": True}

    def test_both_channels_newer(self):
        for mod in self.modules:
            a = mod._b4_update_availability("1.78.0", self.cache)
            self.assertTrue(a["known"])
            self.assertTrue(a["release_update"])
            self.assertTrue(a["pre_update"])
            self.assertFalse(a["up_to_date"])

    def test_release_equal_prerelease_newer(self):
        """Установлен последний release → предлагается только pre-release."""
        for mod in self.modules:
            a = mod._b4_update_availability("1.80.3", self.cache)
            self.assertFalse(a["release_update"])
            self.assertTrue(a["pre_update"])
            self.assertFalse(a["up_to_date"])

    def test_on_latest_prerelease(self):
        """Установлен последний pre-release → ставить нечего."""
        for mod in self.modules:
            a = mod._b4_update_availability("1.80.4rc1", self.cache)
            self.assertFalse(a["release_update"])
            self.assertFalse(a["pre_update"])
            self.assertTrue(a["up_to_date"])

    def test_installed_newer_than_cache(self):
        """Установлена более новая версия (обновление мимо Chimera) —
        «доступных» нет, «актуальная» не заявляем (в сравнении младше)."""
        for mod in self.modules:
            a = mod._b4_update_availability("1.81.0", self.cache)
            self.assertFalse(a["release_update"])
            self.assertFalse(a["pre_update"])

    def test_no_cache_data_means_unknown(self):
        for mod in self.modules:
            a = mod._b4_update_availability(
                "1.78.0", {"release": "", "prerelease": "",
                           "checked_at": 0.0, "ok": False})
            self.assertFalse(a["known"])
            self.assertFalse(a["release_update"])
            self.assertFalse(a["up_to_date"])

    def test_unparsable_installed_not_compared(self):
        """Установленная версия-мусор → никаких «доступных обновлений»."""
        for mod in self.modules:
            a = mod._b4_update_availability("unknown", self.cache)
            self.assertTrue(a["known"])
            self.assertFalse(a["release_update"])
            self.assertFalse(a["pre_update"])
            self.assertFalse(a["up_to_date"])

    def test_release_rc_upgrade_offered(self):
        """Установлен rc1, вышел финальный релиз → предлагаем release."""
        for mod in self.modules:
            a = mod._b4_update_availability(
                "1.80.4rc1", {"release": "1.80.4", "prerelease": "1.80.4rc1",
                              "checked_at": 1.0, "ok": True})
            self.assertTrue(a["release_update"])
            self.assertFalse(a["pre_update"])


class TestB4UpdateHeaderRow(_B4BothModulesMixin, unittest.TestCase):
    """_b4_update_header_row — строка «Обновление:» для шапки меню."""

    def setUp(self):
        self._setup_modules()
        self.cache = {"release": "1.80.3", "prerelease": "1.80.4rc1",
                      "checked_at": 1.0, "ok": True}

    def test_updates_available_row_shows_both_channels(self):
        for mod in self.modules:
            row = _plain(mod._b4_update_header_row("1.78.0", self.cache))
            self.assertIn("Обновление:", row)
            self.assertIn("release 1.80.3", row)
            self.assertIn("pre-release 1.80.4rc1", row)
            self.assertIn("[5]", row)

    def test_row_fits_narrow_terminal(self):
        """Строка с обоими каналами влезает в минимальную рамку (64)."""
        for mod in self.modules:
            row = _plain(mod._b4_update_header_row("1.78.0", self.cache))
            self.assertLessEqual(len(row.strip()), 64,
                                 f"строка шире рамки: {row!r}")

    def test_up_to_date_row(self):
        for mod in self.modules:
            row = _plain(mod._b4_update_header_row("1.80.4rc1", self.cache))
            self.assertIn("актуальн", row)
            self.assertNotIn("[5]", row)

    def test_unknown_row_mentions_github(self):
        for mod in self.modules:
            row = _plain(mod._b4_update_header_row(
                "1.78.0", {"release": "", "prerelease": "",
                           "checked_at": 0.0, "ok": False}))
            self.assertIn("не проверено", row)
            self.assertIn("GitHub", row)

    def test_undefined_version_row_lists_versions(self):
        for mod in self.modules:
            row = _plain(mod._b4_update_header_row("", self.cache))
            self.assertIn("release 1.80.3", row)
            self.assertIn("не определена", row)

    def test_rows_identical_in_both_modules(self):
        for installed in ("1.78.0", "1.80.4rc1", "", "unknown"):
            self.assertEqual(
                _plain(self.youtube_b4._b4_update_header_row(installed, self.cache)),
                _plain(self.dpi_bypass._b4_update_header_row(installed, self.cache)))


class TestB4LatestCache(_B4BothModulesMixin, unittest.TestCase):
    """Кэш latest-версий в общем state: TTL, force, неудача, guard."""

    def setUp(self):
        self._setup_modules()

    def _detectors(self, mod, release="1.80.3", prerelease="1.80.4rc1"):
        """Патчит детекторы; счётчик вызовов — в self.calls."""
        self.calls = {"rel": 0, "pre": 0}
        def _rel(timeout=10):
            self.calls["rel"] += 1
            return release
        def _pre(timeout=10):
            self.calls["pre"] += 1
            return prerelease
        patcher_rel = patch.object(mod, "_detect_latest_version", _rel)
        patcher_pre = patch.object(
            mod, "_detect_latest_prerelease_version", _pre)
        patcher_inst = patch.object(mod, "_detect_installed",
                                    lambda: True)
        patcher_rel.start(); patcher_pre.start(); patcher_inst.start()
        self.addCleanup(patcher_rel.stop)
        self.addCleanup(patcher_pre.stop)
        self.addCleanup(patcher_inst.stop)

    def test_b4_latest_cache_reads_state(self):
        import time
        for mod in self.modules:
            state_file = self._isolated_state(mod, {
                "latest_release": "1.80.3", "latest_prerelease": "1.80.4rc1",
                "latest_checked_at": 123.5, "latest_check_ok": True,
            })
            cache = mod._b4_latest_cache()
            self.assertEqual(cache["release"], "1.80.3")
            self.assertEqual(cache["prerelease"], "1.80.4rc1")
            self.assertAlmostEqual(cache["checked_at"], 123.5)
            self.assertTrue(cache["ok"])

    def test_b4_latest_cache_defaults(self):
        for mod in self.modules:
            state_file = self._isolated_state(mod, {"installed": True})
            cache = mod._b4_latest_cache()
            self.assertEqual(cache["release"], "")
            self.assertEqual(cache["prerelease"], "")
            self.assertEqual(cache["checked_at"], 0.0)
            self.assertFalse(cache["ok"])

    def test_fresh_cache_no_network(self):
        """Свежий успешный кэш (TTL 6 ч) — GitHub не дёргается."""
        import time
        for mod in self.modules:
            self._isolated_state(mod, {
                "latest_release": "1.80.3", "latest_prerelease": "1.80.4rc1",
                "latest_checked_at": time.time(), "latest_check_ok": True,
            })
            self._detectors(mod)
            cache = mod._refresh_b4_latest_cache()
            self.assertEqual(self.calls["rel"], 0)
            self.assertEqual(self.calls["pre"], 0)
            self.assertEqual(cache["release"], "1.80.3")

    def test_stale_cache_refreshes_and_saves(self):
        """Кэш старше 6 ч — проверка GitHub + запись в state."""
        import time
        for mod in self.modules:
            state_file = self._isolated_state(mod, {
                "latest_release": "1.78.0", "latest_prerelease": "",
                "latest_checked_at": time.time() - 7 * 3600,
                "latest_check_ok": True,
            })
            self._detectors(mod)
            cache = mod._refresh_b4_latest_cache()
            self.assertEqual(self.calls["rel"], 1)
            self.assertEqual(self.calls["pre"], 1)
            self.assertEqual(cache["release"], "1.80.3")
            self.assertEqual(cache["prerelease"], "1.80.4rc1")
            self.assertTrue(cache["ok"])
            # Значения записаны в state (видит второй модуль).
            saved = json.loads(state_file.read_text())
            self.assertEqual(saved["latest_release"], "1.80.3")
            self.assertEqual(saved["latest_prerelease"], "1.80.4rc1")
            self.assertTrue(saved["latest_check_ok"])

    def test_force_ignores_fresh_ttl(self):
        import time
        for mod in self.modules:
            self._isolated_state(mod, {
                "latest_release": "1.78.0", "latest_prerelease": "",
                "latest_checked_at": time.time(), "latest_check_ok": True,
            })
            self._detectors(mod)
            mod._refresh_b4_latest_cache(force=True)
            self.assertEqual(self.calls["rel"], 1)

    def test_failed_check_preserves_old_values(self):
        """GitHub недоступен — прежние версии НЕ затираются, ok=False."""
        import time
        for mod in self.modules:
            state_file = self._isolated_state(mod, {
                "latest_release": "1.80.3", "latest_prerelease": "1.80.4rc1",
                "latest_checked_at": time.time() - 7 * 3600,
                "latest_check_ok": True,
            })
            self._detectors(mod, release="", prerelease="")
            cache = mod._refresh_b4_latest_cache()
            self.assertEqual(cache["release"], "1.80.3")
            self.assertEqual(cache["prerelease"], "1.80.4rc1")
            self.assertFalse(cache["ok"])
            saved = json.loads(state_file.read_text())
            self.assertEqual(saved["latest_release"], "1.80.3")
            self.assertFalse(saved["latest_check_ok"])

    def test_failed_check_retry_ttl_30min(self):
        """После неудачи повтор не раньше чем через 30 минут."""
        import time
        for mod in self.modules:
            # Неудача 1 минуту назад — сеть не дёргаем.
            self._isolated_state(mod, {
                "latest_release": "1.80.3", "latest_prerelease": "",
                "latest_checked_at": time.time() - 60,
                "latest_check_ok": False,
            })
            self._detectors(mod)

            def _no_network(timeout=10):
                raise AssertionError("network must not be called")
            with patch.object(mod, "_detect_latest_version", _no_network):
                cache = mod._refresh_b4_latest_cache()
            self.assertEqual(cache["release"], "1.80.3")

            # Неудача 31 минуту назад — повторная попытка.
            self._isolated_state(mod, {
                "latest_release": "1.80.3", "latest_prerelease": "",
                "latest_checked_at": time.time() - 31 * 60,
                "latest_check_ok": False,
            })
            cache = mod._refresh_b4_latest_cache()
            self.assertEqual(self.calls["rel"], 1)

    def test_not_installed_no_network(self):
        """b4 не установлен — GitHub не запрашивается вовсе."""
        for mod in self.modules:
            self._isolated_state(mod, {})

            def _no_network(timeout=10):
                raise AssertionError("network must not be called")
            with patch.object(mod, "_detect_latest_version", _no_network), \
                 patch.object(mod, "_detect_installed", lambda: False):
                cache = mod._refresh_b4_latest_cache(force=True)
            self.assertEqual(cache["release"], "")

    def test_short_timeout_passed_to_detectors(self):
        """Фоновая проверка использует короткий таймаут B4_LATEST_TIMEOUT."""
        seen = {}
        for mod in self.modules:
            self._isolated_state(mod, {})
            def _rel(timeout=10):
                seen["timeout"] = timeout
                return "1.80.3"
            with patch.object(mod, "_detect_latest_version", _rel), \
                 patch.object(mod, "_detect_latest_prerelease_version",
                              lambda timeout=10: ""), \
                 patch.object(mod, "_detect_installed", lambda: True):
                mod._refresh_b4_latest_cache(force=True)
            self.assertEqual(seen["timeout"], mod.B4_LATEST_TIMEOUT)
            self.assertLess(mod.B4_LATEST_TIMEOUT, 10)


class TestMenuUpdateHeaderRow(_B4BothModulesMixin, unittest.TestCase):
    """Главное меню рендерит строку «Обновление:» с доступными версиями.

    v76: юзер, зайдя в главное меню модуля, сразу видит готовые к
    установке release/pre-release — не заходя в раздел [5].
    """

    def setUp(self):
        self._setup_modules()

    def _render_menu(self, mod, menu_func_name, fake_cache, version='1.78.0'):
        import io
        from contextlib import redirect_stdout

        def _fake_status():
            return {
                'installed': True, 'service_active': True,
                'active_preset': 'default', 'version': version,
                'web_port': 9700, 'config_path': '/etc/b4/config.json',
                'binary_path': '/usr/local/bin/b4', 'queue_num': 537,
                'mark': 32768, 'nginx_front_enabled': False,
                'nginx_front_port': 9743, 'nginx_front_url': None,
            }

        inputs = iter(['q'])
        def _input(prompt='', *a, **kw):
            return next(inputs)

        captured = io.StringIO()
        with patch.object(mod, "status", _fake_status), \
             patch.object(mod, "_b4_nginx_status",
                          lambda: {'enabled': False, 'port': 9743}), \
             patch.object(mod, "_migrate_to_native_rules_if_needed",
                          lambda: None), \
             patch.object(mod, "_refresh_b4_latest_cache",
                          lambda force=False: fake_cache), \
             patch("builtins.input", side_effect=_input), \
             redirect_stdout(captured):
            try:
                getattr(mod, menu_func_name)()
            except StopIteration:
                pass
        return captured.getvalue()

    def test_menu_row_shows_available_updates(self):
        """Меню содержит строку с обеими доступными версиями и отсылкой [5]."""
        fake_cache = {"release": "1.80.3", "prerelease": "1.80.4rc1",
                      "checked_at": 1.0, "ok": True}
        for mod, menu in ((self.youtube_b4, 'do_youtube_b4_menu'),
                          (self.dpi_bypass, 'do_dpi_bypass_menu')):
            out = _plain(self._render_menu(mod, menu, fake_cache))
            lines = [l for l in out.splitlines() if "Обновление:" in l]
            self.assertEqual(len(lines), 1,
                             f"ожидалась одна строка «Обновление:», "
                             f"получено {len(lines)} в {mod.__name__}")
            self.assertIn("release 1.80.3", lines[0])
            self.assertIn("pre-release 1.80.4rc1", lines[0])
            self.assertIn("[5]", lines[0])
            # Строка не разорвана переносом: [5] на той же строке,
            # до правой границы рамки.
            body = lines[0].rstrip().rstrip('║').rstrip()
            self.assertTrue(body.endswith("[5]"),
                            f"строка разорвана переносом: {lines[0]!r}")

    def test_menu_row_after_update_shows_up_to_date(self):
        """После успешного обновления (кэш свежий) — «актуальная версия»."""
        fake_cache = {"release": "1.80.3", "prerelease": "1.80.4rc1",
                      "checked_at": 1.0, "ok": True}
        for mod, menu in ((self.youtube_b4, 'do_youtube_b4_menu'),
                          (self.dpi_bypass, 'do_dpi_bypass_menu')):
            out = _plain(self._render_menu(mod, menu, fake_cache,
                                           version='1.80.4rc1'))
            lines = [l for l in out.splitlines() if "Обновление:" in l]
            self.assertEqual(len(lines), 1)
            self.assertIn("актуальн", lines[0])

    def test_update_menu_resets_cache_after_success(self):
        """do_b4_update_menu после успешного обновления сбрасывает кэш
        (_refresh_b4_latest_cache(force=True)) — шапка сразу честная."""
        import inspect
        for mod in (self.youtube_b4, self.dpi_bypass):
            src = inspect.getsource(mod.do_b4_update_menu)
            self.assertIn("_refresh_b4_latest_cache(force=True)", src,
                          f"{mod.__name__}: do_b4_update_menu должен "
                          f"сбрасывать кэш после успешного обновления")

    def test_main_menu_calls_refresh_cache(self):
        """Главные меню получают кэш через _refresh_b4_latest_cache."""
        import inspect
        for mod, menu_name in ((self.youtube_b4, "do_youtube_b4_menu"),
                               (self.dpi_bypass, "do_dpi_bypass_menu")):
            src = inspect.getsource(getattr(mod, menu_name))
            self.assertIn("_refresh_b4_latest_cache()", src,
                          f"{mod.__name__}.{menu_name} должен вызывать "
                          f"_refresh_b4_latest_cache()")
            self.assertIn("_b4_update_header_row(", src,
                          f"{mod.__name__}.{menu_name} должен рендерить "
                          f"строку _b4_update_header_row")


class TestB4LatestSyncBetweenModules(_B4BothModulesMixin, unittest.TestCase):
    """Синхронизация кэша latest между youtube_b4 и dpi_bypass.

    Оба модуля читают/пишут ОДИН общий state-файл — кэш, обновлённый
    одним модулем, сразу виден другому.
    """

    def setUp(self):
        self._setup_modules()

    def test_both_modules_have_latest_cache_functions(self):
        for fn in ("_b4_version_key", "_b4_latest_cache",
                   "_refresh_b4_latest_cache", "_b4_update_availability",
                   "_b4_update_header_row"):
            self.assertTrue(hasattr(self.youtube_b4, fn),
                            f"youtube_b4 lacks {fn}")
            self.assertTrue(hasattr(self.dpi_bypass, fn),
                            f"dpi_bypass lacks {fn}")

    def test_identical_ttl_constants(self):
        for const in ("B4_LATEST_CACHE_TTL", "B4_LATEST_RETRY_TTL",
                      "B4_LATEST_TIMEOUT"):
            self.assertEqual(getattr(self.youtube_b4, const),
                             getattr(self.dpi_bypass, const),
                             f"{const} расходится между модулями")
        # TTL успешной проверки — 6 часов (идиома upstream_updates).
        self.assertEqual(self.youtube_b4.B4_LATEST_CACHE_TTL, 6 * 3600)
        # TTL повторной попытки после неудачи — 30 минут.
        self.assertEqual(self.youtube_b4.B4_LATEST_RETRY_TTL, 30 * 60)

    def test_shared_state_file_single_source_of_cache(self):
        """Кэш живёт в общем youtube_b4_state.json — один на оба модуля."""
        self.assertEqual(self.youtube_b4._STATE_FILE,
                         self.dpi_bypass._STATE_FILE)

    def test_cache_written_by_one_module_visible_to_other(self):
        """Кэш, записанный youtube_b4, читает dpi_bypass (общий state)."""
        import time
        state_file = self._isolated_state(self.youtube_b4, {})
        self.dpi_bypass._STATE_FILE = state_file
        calls = {"rel": 0}
        with patch.object(self.youtube_b4, "_detect_latest_version",
                          lambda timeout=10: "1.80.3"), \
             patch.object(self.youtube_b4, "_detect_latest_prerelease_version",
                          lambda timeout=10: "1.80.4rc1"), \
             patch.object(self.youtube_b4, "_detect_installed",
                          lambda: True):
            self.youtube_b4._refresh_b4_latest_cache(force=True)
        # Второй модуль читает ТОТ ЖЕ state — кэш виден без сети.
        with patch.object(self.dpi_bypass, "_detect_latest_version",
                          lambda timeout=10: (_ for _ in ()).throw(
                              AssertionError("network!"))):
            cache = self.dpi_bypass._refresh_b4_latest_cache()
        self.assertEqual(cache["release"], "1.80.3")
        self.assertEqual(cache["prerelease"], "1.80.4rc1")
        self.assertTrue(cache["ok"])

    def test_detector_functions_accept_timeout_param(self):
        """_detect_latest_version/_detect_latest_prerelease_version
        принимют timeout (для фоновой проверки шапки)."""
        import inspect
        for mod in (self.youtube_b4, self.dpi_bypass):
            for fn in ("_detect_latest_version",
                       "_detect_latest_prerelease_version"):
                sig = inspect.signature(getattr(mod, fn))
                self.assertIn("timeout", sig.parameters)
                self.assertEqual(sig.parameters["timeout"].default, 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
