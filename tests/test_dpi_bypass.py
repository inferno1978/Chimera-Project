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
        # Трекаем вызовы apply_routing_for_set
        self._routing_calls = []
        self._orig_apply = self.dpi_bypass.apply_routing_for_set

        def _fake_apply(set_id, domains):
            self._routing_calls.append((set_id, list(domains)))
            return True

        self.dpi_bypass.apply_routing_for_set = _fake_apply

    def tearDown(self):
        # Восстанавливаем оригинал на случай если кто-то ещё использует модуль
        self.dpi_bypass.apply_routing_for_set = self._orig_apply

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

    def test_missing_id_gets_default(self):
        """Set без id получает дефолтный 'youtube-custom'."""
        test_json = json.dumps({
            "name": "No ID Set",
            "targets": {"sni_domains": ["x.com"]},
        })
        result = self.dpi_bypass.import_custom_set(test_json)
        self.assertTrue(result)
        saved = json.loads(self._config_file.read_text())
        self.assertEqual(saved["sets"][0]["id"], "youtube-custom")
        # Routing вызван с дефолтным id
        self.assertEqual(self._routing_calls,
                         [("youtube-custom", ["x.com"])])

    def test_geosite_categories_removed_without_geosite_path(self):
        """geosite_categories убирается если нет geosite_path."""
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
        # geosite_categories должен быть убран
        self.assertNotIn("geosite_categories",
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
    Сравнивает: домены, fake SNI (sni_type, ttl, sni on/off), TCP-фрагментацию.
    НЕ сравнивает: id, name, b4_version, enabled.
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

    def test_returns_unknown_when_sets_empty(self):
        """Пустой массив sets → ('unknown', None)."""
        self._config_file.write_text(json.dumps({"sets": []}))
        result = self.dpi_bypass._detect_active_preset_from_config()
        self.assertEqual(result, ("unknown", None))

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

    def test_default_preset_shows_label(self):
        """Default preset → показывает 'Эталон (DuckDuckGo fake + combo)'."""
        line = self._render_menu_preset_line(self.dpi_bypass.DEFAULT_SET_YOUTUBE, "default")
        self.assertIsNotNone(line)
        self.assertIn("Эталон", line)
        self.assertIn("DuckDuckGo", line)

    def test_aggressive_preset_shows_label(self):
        """Aggressive preset → показывает 'Агрессивный'."""
        line = self._render_menu_preset_line(self.dpi_bypass.AGGRESSIVE_SET_YOUTUBE, "aggressive")
        self.assertIsNotNone(line)
        self.assertIn("Агрессивный", line)

    def test_custom_preset_shows_custom_with_set_name(self):
        """REGRESSION: custom preset → показывает 'custom (имя_seta)'.

        Ранее показывал устаревшее имя preset'а из state.json.
        """
        # Создаём модифицированный set (добавлен домен)
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        original_domains = list(modified["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        modified["name"] = "Youtube-Extended"
        # State.json говорит 'default', но config — модифицированный
        line = self._render_menu_preset_line(modified, "default")
        self.assertIsNotNone(line)
        self.assertIn("custom", line)
        self.assertIn("Youtube-Extended", line)
        # НЕ должен показывать устаревшее 'Эталон'
        self.assertNotIn("Эталон", line)

    def test_custom_preset_without_name_shows_just_custom(self):
        """Custom set без name → показывает просто 'custom'."""
        modified = dict(self.dpi_bypass.DEFAULT_SET_YOUTUBE)
        original_domains = list(modified["targets"]["sni_domains"])
        modified["targets"] = {"sni_domains": original_domains + ["extra.com"]}
        modified.pop("name", None)
        line = self._render_menu_preset_line(modified, "default")
        self.assertIsNotNone(line)
        self.assertIn("custom", line)
        # Не должно быть '()' (пустых скобок)
        self.assertNotIn("()", line)


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
        """_iptables_apply() в youtube_b4 НЕ ставит IPv4 правила (только IPv6)."""
        import inspect
        src = inspect.getsource(self.youtube_b4._iptables_apply)
        # НЕ должно быть iptables -t mangle -A b4_mangle (IPv4)
        self.assertNotIn('"-A", "b4_mangle"', src,
                         "_iptables_apply() НЕ должен ставить IPv4 правила")
        # ДОЛЖНО быть ip6tables (IPv6 fallback)
        self.assertIn("ip6tables", src,
                      "_iptables_apply() ДОЛЖЕН ставить IPv6 fallback правила")

    def test_iptables_apply_no_ipv4_rules_dpi_bypass(self):
        """_iptables_apply() в dpi_bypass НЕ ставит IPv4 правила (только IPv6)."""
        import inspect
        src = inspect.getsource(self.dpi_bypass._iptables_apply)
        self.assertNotIn('"-A", "b4_mangle"', src,
                         "_iptables_apply() НЕ должен ставить IPv4 правила")
        self.assertIn("ip6tables", src,
                      "_iptables_apply() ДОЛЖЕН ставить IPv6 fallback правила")

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

    def test_both_modules_have_ipv6_fallback(self):
        """Оба модуля имеют IPv6 fallback в _iptables_apply()."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._iptables_apply)
        dpi_src = inspect.getsource(self.dpi_bypass._iptables_apply)
        self.assertIn("ip6tables", yt_src)
        self.assertIn("ip6tables", dpi_src)
        self.assertIn("b4_mangle6", yt_src)
        self.assertIn("b4_mangle6", dpi_src)

    def test_both_modules_no_ipv4_apply(self):
        """Оба модуля НЕ ставят IPv4 правила в _iptables_apply()."""
        import inspect
        yt_src = inspect.getsource(self.youtube_b4._iptables_apply)
        dpi_src = inspect.getsource(self.dpi_bypass._iptables_apply)
        # Не должно быть "-A", "b4_mangle" (IPv4 add rule)
        self.assertNotIn('"-A", "b4_mangle"', yt_src)
        self.assertNotIn('"-A", "b4_mangle"', dpi_src)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
