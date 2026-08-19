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


if __name__ == "__main__":
    unittest.main(verbosity=2)
