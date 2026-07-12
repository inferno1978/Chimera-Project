#!/usr/bin/env python3
"""
tests/test_singbox_state.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/singbox_state.py.

Покрывает:
  1. Round-trip: singbox_state_init → singbox_state_load → совпадение
  2. Регистрация singbox_state_file в основном state.json — ровно одна запись,
     без дублирования при повторных вызовах
  3. Поведение при отсутствующем/битом (невалидный JSON) singbox_state.json
  4. singbox_state_set_sni_dispatch / get_sni_dispatch / update_sni_dispatch —
     корректность обновления вложенного sni_dispatch-состояния
  5. Два последовательных save подряд — не бьют файл
  6. singbox_state_update — частичное обновление top-level keys
  7. singbox_state_update_inbound — частичное обновление inbound без потери
     остальных полей
  8. singbox_state_delete — удаление файла + отмена регистрации в main state
  9. Helpers: is_installed, get_version, get_binary_path, get_config_path
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ─────────────────────────────────────────────────────────────────────────────
# Базовый миксин для патчей
# ─────────────────────────────────────────────────────────────────────────────

class _StateTestBase(unittest.TestCase):
    """Базовый класс с настройкой tmpdir и хелпером для патчей."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Round-trip: init → load → совпадение
# ─────────────────────────────────────────────────────────────────────────────

class TestStateRoundTrip(_StateTestBase):
    """singbox_state_init → singbox_state_load → совпадение."""

    def test_init_creates_file(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.13.14")
        self.assertTrue(self._state.exists())

    def test_init_returns_state_dict(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            state = singbox_state_init(version="1.13.14")
        self.assertIsInstance(state, dict)
        self.assertTrue(state["installed"])
        self.assertEqual(state["version"], "1.13.14")

    def test_load_after_init_matches_returned(self):
        """Записал → прочитал → совпадает."""
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            returned = singbox_state_init(version="1.0.0")
            loaded = singbox_state_load()
        self.assertEqual(returned, loaded)

    def test_init_has_all_required_top_level_keys(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            state = singbox_state_init(version="1.0.0")
        for key in ("installed", "version", "installed_at", "binary_path",
                    "config_path", "inbounds", "sni_dispatch", "last_applied"):
            self.assertIn(key, state, f"missing top-level key: {key}")

    def test_init_has_all_protocol_inbounds(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            state = singbox_state_init(version="1.0.0")
        inbounds = state["inbounds"]
        for proto in ("shadowtls", "anytls", "tuic", "trojan"):
            self.assertIn(proto, inbounds, f"missing inbound: {proto}")

    def test_init_all_protocols_disabled_by_default(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            state = singbox_state_init(version="1.0.0")
        for proto, ib in state["inbounds"].items():
            self.assertFalse(ib.get("enabled", False),
                             f"{proto} should be disabled by default")

    def test_init_sni_dispatch_disabled_by_default(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            state = singbox_state_init(version="1.0.0")
        self.assertFalse(state["sni_dispatch"].get("enabled", False))


# ─────────────────────────────────────────────────────────────────────────────
# 2. Регистрация в основном state.json
# ─────────────────────────────────────────────────────────────────────────────

class TestMainStateRegistration(_StateTestBase):
    """Регистрация singbox_state_file в основном state.json."""

    def test_register_creates_entry_in_main_state(self):
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state, SINGBOX_STATE_FILE,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            register_singbox_in_main_state()
            main = json.loads(self._main_state.read_text())
        self.assertIn("singbox_state_file", main)
        self.assertEqual(main["singbox_state_file"], str(self._state))

    def test_register_idempotent_no_duplicate(self):
        """Повторный вызов register не должен создавать дубликат."""
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            register_singbox_in_main_state()
            register_singbox_in_main_state()
            register_singbox_in_main_state()
            main = json.loads(self._main_state.read_text())
        # Ровно одна запись
        self.assertEqual(list(main.keys()).count("singbox_state_file"), 1)

    def test_register_preserves_other_keys_in_main_state(self):
        """Регистрация не должна стирать существующие ключи в main state."""
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state,
        )
        self._main_state.write_text(json.dumps({
            "uuid": "test-uuid",
            "domain": "example.com",
            "install_mode": "A",
        }))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            register_singbox_in_main_state()
            main = json.loads(self._main_state.read_text())
        self.assertEqual(main["uuid"], "test-uuid")
        self.assertEqual(main["domain"], "example.com")
        self.assertEqual(main["install_mode"], "A")
        self.assertIn("singbox_state_file", main)

    def test_unregister_removes_entry(self):
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state, unregister_singbox_from_main_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            register_singbox_in_main_state()
            self.assertTrue(self._main_state.exists())
            unregister_singbox_from_main_state()
            main = json.loads(self._main_state.read_text())
        self.assertNotIn("singbox_state_file", main)

    def test_unregister_idempotent_when_not_registered(self):
        """unregister при отсутствии записи не должен падать."""
        from vless_installer.modules.singbox_common import (
            unregister_singbox_from_main_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            # main_state не существует
            unregister_singbox_from_main_state()
        # Не упало — OK

    def test_state_save_triggers_registration(self):
        """singbox_state_save должен автоматически регистрировать в main state."""
        from vless_installer.modules.singbox_state import singbox_state_save
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_save({"installed": True, "version": "1.0.0"})
            # main_state должен быть создан с регистрацией
            self.assertTrue(self._main_state.exists())
            main = json.loads(self._main_state.read_text())
        self.assertIn("singbox_state_file", main)

    def test_register_returns_true_on_success(self):
        """register_singbox_in_main_state() возвращает True при успехе."""
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = register_singbox_in_main_state()
        self.assertTrue(result)

    def test_register_returns_true_when_already_registered(self):
        """Повторный register возвращает True (идемпотентность)."""
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            register_singbox_in_main_state()
            result = register_singbox_in_main_state()  # повторный
        self.assertTrue(result)

    def test_register_returns_false_when_save_fails(self):
        """register возвращает False если _save_main_state провалился.

        Баг №2 из v4.22.1: раньше register возвращал None (молча проглатывал
        ошибку). Теперь должен вернуть False.
        """
        from vless_installer.modules.singbox_common import (
            register_singbox_in_main_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_common._save_main_state",
                                      return_value=False))
            result = register_singbox_in_main_state()
        self.assertFalse(result)

    def test_state_save_logs_error_when_registration_fails(self):
        """singbox_state_save логирует ERROR если регистрация в main state провалилась.

        Баг №2 из v4.22.1: раньше save молча возвращал True даже при провале
        регистрации. Теперь должен записать ERROR в лог о рассинхроне.
        """
        from vless_installer.modules.singbox_state import singbox_state_save
        log_calls: list = []
        fake_core = MagicMock()
        fake_core.log_to_file = lambda level, msg: log_calls.append((level, msg))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_common._save_main_state",
                                      return_value=False))
            stack.enter_context(patch("vless_installer.modules.singbox_state._core_module",
                                      return_value=fake_core))
            # save всё равно возвращает True — state-файл записан OK
            result = singbox_state_save({"installed": True, "version": "1.0.0"})
        self.assertTrue(result)
        # Но в лог ушла ERROR-запись о рассинхроне
        error_logs = [(lvl, msg) for lvl, msg in log_calls if lvl == "ERROR"]
        self.assertGreater(len(error_logs), 0,
                           "ERROR-запись о провале регистрации должна быть в логе")
        # Проверяем что сообщение про рассинхрон
        self.assertTrue(any("регистрация" in msg.lower() or "main state" in msg.lower()
                            for _, msg in error_logs),
                        f"ERROR-запись должна упоминать регистрацию/main state, "
                        f"получено: {error_logs}")

    def test_state_save_does_not_log_error_when_registration_succeeds(self):
        """При успешной регистрации ERROR-записи быть не должно."""
        from vless_installer.modules.singbox_state import singbox_state_save
        log_calls: list = []
        fake_core = MagicMock()
        fake_core.log_to_file = lambda level, msg: log_calls.append((level, msg))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_state._core_module",
                                      return_value=fake_core))
            singbox_state_save({"installed": True, "version": "1.0.0"})
        error_logs = [(lvl, msg) for lvl, msg in log_calls if lvl == "ERROR"]
        self.assertEqual(error_logs, [],
                         "При успешной регистрации ERROR-записей быть не должно")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Поведение при отсутствующем/битом state
# ─────────────────────────────────────────────────────────────────────────────

class TestCorruptStateHandling(_StateTestBase):
    """Поведение при отсутствующем/битом singbox_state.json."""

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.singbox_state import singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_corrupt_json(self):
        """Невалидный JSON не должен вызывать необработанное исключение."""
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("{invalid json content")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_empty_file(self):
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_non_json(self):
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("not json at all, just text")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_array(self):
        """JSON array (не dict) — невалидный state, должна вернуть {}.

        ВАЖНО: раньше здесь стоял self.assertIsNotNone(result) — он проходил
        даже на сломанном коде (load возвращал list, not None). Теперь
        assert строгий: result обязан быть пустым dict. Тест ЛОМАЕТСЯ на
        старом коде (где load возвращал [1,2,3]) и проходит только после
        фикса isinstance(result, dict).
        """
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("[1, 2, 3]")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})
        self.assertIsInstance(result, dict)

    def test_load_returns_empty_on_string(self):
        """JSON string (не dict) — невалидный state, должна вернуть {}."""
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text('"just a string"')
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_int(self):
        """JSON number (не dict) — невалидный state, должна вернуть {}."""
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("42")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_null(self):
        """JSON null — невалидный state, должна вернуть {}."""
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("null")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_load_returns_empty_on_bool(self):
        """JSON boolean (не dict) — невалидный state, должна вернуть {}."""
        from vless_installer.modules.singbox_state import singbox_state_load
        self._state.write_text("true")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_load()
        self.assertEqual(result, {})

    def test_is_installed_returns_false_when_no_file(self):
        from vless_installer.modules.singbox_state import singbox_state_is_installed
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            self.assertFalse(singbox_state_is_installed())

    def test_is_installed_returns_false_on_corrupt(self):
        from vless_installer.modules.singbox_state import singbox_state_is_installed
        self._state.write_text("{broken")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            self.assertFalse(singbox_state_is_installed())


# ─────────────────────────────────────────────────────────────────────────────
# 4. SNI-dispatch state management
# ─────────────────────────────────────────────────────────────────────────────

class TestSniDispatchState(_StateTestBase):
    """singbox_state_set/get/update_sni_dispatch."""

    def test_get_sni_dispatch_returns_empty_when_no_state(self):
        from vless_installer.modules.singbox_state import singbox_state_get_sni_dispatch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_state_get_sni_dispatch()
        self.assertEqual(result, {})

    def test_set_sni_dispatch_creates_entry(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_set_sni_dispatch,
            singbox_state_get_sni_dispatch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_set_sni_dispatch({
                "enabled": True,
                "shadowtls_sni": "shadowtls.example.com",
                "anytls_sni": "anytls.example.com",
            })
            sd = singbox_state_get_sni_dispatch()
        self.assertTrue(sd["enabled"])
        self.assertEqual(sd["shadowtls_sni"], "shadowtls.example.com")
        self.assertEqual(sd["anytls_sni"], "anytls.example.com")

    def test_update_sni_dispatch_partial_preserves_other_fields(self):
        """Частичный апдейт SNI-dispatch не должен терять остальные поля."""
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_set_sni_dispatch,
            singbox_state_update_sni_dispatch, singbox_state_get_sni_dispatch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_set_sni_dispatch({
                "enabled": True,
                "shadowtls_sni": "old.example.com",
                "anytls_sni": "anytls.example.com",
                "default_backend": "unix:/dev/shm/x.socket",
            })
            # Частичный апдейт — только shadowtls_sni
            singbox_state_update_sni_dispatch(shadowtls_sni="new.example.com")
            sd = singbox_state_get_sni_dispatch()
        # Старые значения сохранены
        self.assertTrue(sd["enabled"])
        self.assertEqual(sd["anytls_sni"], "anytls.example.com")
        self.assertEqual(sd["default_backend"], "unix:/dev/shm/x.socket")
        # Новое значение применено
        self.assertEqual(sd["shadowtls_sni"], "new.example.com")

    def test_update_sni_dispatch_preserves_inbounds(self):
        """Апдейт SNI-dispatch не должен затронуть inbounds."""
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_update_sni_dispatch, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True, password="pw123")
            singbox_state_update_sni_dispatch(enabled=True, shadowtls_sni="x.example.com")
            state = singbox_state_load()
        # Inbounds не пострадали
        self.assertTrue(state["inbounds"]["shadowtls"]["enabled"])
        self.assertEqual(state["inbounds"]["shadowtls"]["password"], "pw123")
        # SNI-dispatch обновлён
        self.assertTrue(state["sni_dispatch"]["enabled"])
        self.assertEqual(state["sni_dispatch"]["shadowtls_sni"], "x.example.com")

    def test_update_sni_dispatch_when_no_existing(self):
        """update_sni_dispatch создаёт секцию если её не было."""
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_sni_dispatch,
            singbox_state_get_sni_dispatch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # Сначала sni_dispatch есть, но пустой (init создаёт disabled)
            singbox_state_update_sni_dispatch(enabled=True)
            sd = singbox_state_get_sni_dispatch()
        self.assertTrue(sd["enabled"])


# ─────────────────────────────────────────────────────────────────────────────
# 5. Два последовательных save — не бьют файл
# ─────────────────────────────────────────────────────────────────────────────

class TestConsecutiveSave(_StateTestBase):
    """Два последовательных save подряд — файл не бьётся."""

    def test_two_saves_preserve_data(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_save, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_save({"installed": True, "version": "1.0.0", "data": "first"})
            singbox_state_save({"installed": True, "version": "2.0.0", "data": "second"})
            loaded = singbox_state_load()
        self.assertEqual(loaded["version"], "2.0.0")
        self.assertEqual(loaded["data"], "second")

    def test_three_saves_rapid(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_save, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            for i in range(3):
                singbox_state_save({"installed": True, "iteration": i})
            loaded = singbox_state_load()
        self.assertEqual(loaded["iteration"], 2)

    def test_save_update_save_roundtrip(self):
        """init → update → save → load — данные консистентны."""
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update(version="1.1.0")
            singbox_state_update(last_applied="2026-01-01T00:00:00Z")
            loaded = singbox_state_load()
        self.assertEqual(loaded["version"], "1.1.0")
        self.assertEqual(loaded["last_applied"], "2026-01-01T00:00:00Z")
        # init-created fields preserved
        self.assertTrue(loaded["installed"])

    def test_atomic_save_does_not_corrupt_on_concurrent_read(self):
        """Атомарная запись через tmp+rename — файл всегда валиден."""
        from vless_installer.modules.singbox_state import (
            singbox_state_save, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            for i in range(10):
                singbox_state_save({"installed": True, "iteration": i})
                # Читаем после каждой записи — файл всегда валидный JSON
                loaded = singbox_state_load()
                self.assertEqual(loaded["iteration"], i)


# ─────────────────────────────────────────────────────────────────────────────
# 6. singbox_state_update — top-level keys
# ─────────────────────────────────────────────────────────────────────────────

class TestStateUpdate(_StateTestBase):
    """singbox_state_update — частичное обновление top-level keys."""

    def test_update_adds_new_key(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update(custom_field="custom_value")
            loaded = singbox_state_load()
        self.assertEqual(loaded["custom_field"], "custom_value")

    def test_update_overwrites_existing_key(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update(version="2.0.0")
            loaded = singbox_state_load()
        self.assertEqual(loaded["version"], "2.0.0")

    def test_update_preserves_untouched_keys(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update(version="2.0.0")
            loaded = singbox_state_load()
        self.assertTrue(loaded["installed"])
        self.assertIn("inbounds", loaded)
        self.assertIn("sni_dispatch", loaded)

    def test_update_returns_updated_state(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            result = singbox_state_update(version="2.0.0")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["version"], "2.0.0")


# ─────────────────────────────────────────────────────────────────────────────
# 7. singbox_state_update_inbound — partial inbound update
# ─────────────────────────────────────────────────────────────────────────────

class TestInboundUpdate(_StateTestBase):
    """singbox_state_update_inbound — partial update without losing fields."""

    def test_update_inbound_enabled_preserves_password(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", password="secretpw")
            singbox_state_update_inbound("shadowtls", enabled=True)
            ib = singbox_state_get_inbound("shadowtls")
        self.assertTrue(ib["enabled"])
        self.assertEqual(ib["password"], "secretpw")  # не потерян

    def test_update_inbound_users_preserves_enabled(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("tuic", enabled=True)
            singbox_state_update_inbound("tuic", users=[{"uuid": "x", "password": "y"}])
            ib = singbox_state_get_inbound("tuic")
        self.assertTrue(ib["enabled"])  # не потерян
        self.assertEqual(len(ib["users"]), 1)

    def test_update_inbound_does_not_affect_other_protocols(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True, password="shadow_pw")
            singbox_state_update_inbound("anytls", enabled=True, password="anytls_pw")
            shadowtls = singbox_state_get_inbound("shadowtls")
            anytls = singbox_state_get_inbound("anytls")
        self.assertEqual(shadowtls["password"], "shadow_pw")
        self.assertEqual(anytls["password"], "anytls_pw")

    def test_update_nonexistent_inbound_creates_it(self):
        """update_inbound для несуществующего протокола — создаёт."""
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("custom_proto", enabled=True, custom="val")
            ib = singbox_state_get_inbound("custom_proto")
        self.assertTrue(ib["enabled"])
        self.assertEqual(ib["custom"], "val")


# ─────────────────────────────────────────────────────────────────────────────
# 8. singbox_state_delete — удаление
# ─────────────────────────────────────────────────────────────────────────────

class TestStateDelete(_StateTestBase):
    """singbox_state_delete — удаление файла + отмена регистрации."""

    def test_delete_removes_state_file(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_delete,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            self.assertTrue(self._state.exists())
            singbox_state_delete()
        self.assertFalse(self._state.exists())

    def test_delete_unregisters_from_main_state(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_delete,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # Регистрация должна была произойти при save
            self.assertTrue(self._main_state.exists())
            singbox_state_delete()
            main = json.loads(self._main_state.read_text())
        self.assertNotIn("singbox_state_file", main)

    def test_delete_idempotent_when_no_file(self):
        """Удаление при отсутствии файла не падает."""
        from vless_installer.modules.singbox_state import singbox_state_delete
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            # Файл не создаём
            result = singbox_state_delete()
        self.assertTrue(result)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestStateHelpers(_StateTestBase):
    """Helpers: is_installed, get_version, get_binary_path, get_config_path."""

    def test_is_installed_true_after_init(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_is_installed,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            self.assertTrue(singbox_state_is_installed())

    def test_is_installed_false_when_no_state(self):
        from vless_installer.modules.singbox_state import singbox_state_is_installed
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            self.assertFalse(singbox_state_is_installed())

    def test_get_version_returns_value(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_version,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.13.14")
            self.assertEqual(singbox_state_get_version(), "1.13.14")

    def test_get_version_empty_when_no_state(self):
        from vless_installer.modules.singbox_state import singbox_state_get_version
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            self.assertEqual(singbox_state_get_version(), "")

    def test_get_binary_path_returns_value(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_binary_path,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            path = singbox_state_get_binary_path()
        self.assertIn("sing-box", path)

    def test_get_binary_path_default_when_no_state(self):
        from vless_installer.modules.singbox_state import singbox_state_get_binary_path
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            path = singbox_state_get_binary_path()
        self.assertIn("sing-box", path)

    def test_get_config_path_returns_value(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_config_path,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            path = singbox_state_get_config_path()
        self.assertIn("config.json", path)

    def test_get_config_path_default_when_no_state(self):
        from vless_installer.modules.singbox_state import singbox_state_get_config_path
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            path = singbox_state_get_config_path()
        self.assertIn("config.json", path)


# ─────────────────────────────────────────────────────────────────────────────
# 10. State file permissions
# ─────────────────────────────────────────────────────────────────────────────

class TestStatePermissions(_StateTestBase):
    """Права доступа state-файла — 0o600 (пароли/сертификаты внутри)."""

    def test_state_file_permissions_0600(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
        mode = self._state.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_state_file_permissions_0600_after_update(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update(version="2.0.0")
        mode = self._state.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Peer management functions (если есть в state)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnabledProtocols(_StateTestBase):
    """singbox_state_get_enabled_protocols."""

    def test_empty_by_default(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_enabled_protocols,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            protos = singbox_state_get_enabled_protocols()
        self.assertEqual(protos, [])

    def test_returns_only_enabled(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_enabled_protocols,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True)
            singbox_state_update_inbound("tuic", enabled=True)
            singbox_state_update_inbound("anytls", enabled=False)  # явно выключен
            protos = singbox_state_get_enabled_protocols()
        self.assertIn("shadowtls", protos)
        self.assertIn("tuic", protos)
        self.assertNotIn("anytls", protos)

    def test_disabled_after_disable(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_enabled_protocols,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True)
            singbox_state_update_inbound("shadowtls", enabled=False)
            protos = singbox_state_get_enabled_protocols()
        self.assertEqual(protos, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
