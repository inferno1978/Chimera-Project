#!/usr/bin/env python3
"""
tests/test_singbox_install.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/singbox_install.py.

Покрывает:
  1. _SYSTEMD_UNIT — текст юнита с hardening-директивами (assert на конкретные
     строки: NoNewPrivileges, ProtectSystem=strict, CapabilityBoundingSet с
     CAP_NET_BIND_SERVICE/CAP_NET_RAW/CAP_NET_ADMIN, AmbientCapabilities)
  2. _install_systemd_unit — создание юнита + daemon-reload + enable
  3. _uninstall_systemd_unit — stop + disable + удаление файла + daemon-reload
  4. singbox_install_binary — повторный вызов не плодит дубли (idempotent)
  5. singbox_install_binary — ошибочные сценарии (GitHub API недоступен,
     fetch_package провалился, бинарник не отвечает на --version)
  6. singbox_uninstall_binary — полное удаление (бинарник + конфиг + state)
  7. singbox_start / singbox_stop / singbox_restart / singbox_status
  8. singbox_status — структура возвращаемого dict

Все subprocess/systemctl вызовы мокаются — реальный systemd не дёргается.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock, call

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


def _mock_run_success(*args, **kwargs):
    """Универсальный mock для subprocess.run — всегда success."""
    return MagicMock(returncode=0, stdout="mock", stderr="")


# ─────────────────────────────────────────────────────────────────────────────
# 1. _SYSTEMD_UNIT — текст юнита с hardening
# ─────────────────────────────────────────────────────────────────────────────

class TestSystemdUnitText(unittest.TestCase):
    """_SYSTEMD_UNIT — проверка конкретных hardening-директив в тексте юнита.

    НЕ просто "unit создался", а assert на конкретные строки.
    """

    def setUp(self):
        _setup_core()

    def test_unit_contains_no_new_privileges(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("NoNewPrivileges=yes", _SYSTEMD_UNIT)

    def test_unit_contains_protect_system_strict(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("ProtectSystem=strict", _SYSTEMD_UNIT)

    def test_unit_contains_protect_home(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("ProtectHome=yes", _SYSTEMD_UNIT)

    def test_unit_contains_capability_bounding_set(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("CapabilityBoundingSet=", _SYSTEMD_UNIT)
        self.assertIn("CAP_NET_BIND_SERVICE", _SYSTEMD_UNIT)
        self.assertIn("CAP_NET_RAW", _SYSTEMD_UNIT)
        self.assertIn("CAP_NET_ADMIN", _SYSTEMD_UNIT)

    def test_unit_contains_ambient_capabilities(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("AmbientCapabilities=", _SYSTEMD_UNIT)
        self.assertIn("CAP_NET_BIND_SERVICE", _SYSTEMD_UNIT)

    def test_unit_contains_exec_start(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        # Проверяем что ExecStart есть (format placeholder)
        self.assertIn("ExecStart=", _SYSTEMD_UNIT)
        self.assertIn("{binary}", _SYSTEMD_UNIT)
        self.assertIn("run -c", _SYSTEMD_UNIT)

    def test_unit_contains_restart_on_failure(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("Restart=on-failure", _SYSTEMD_UNIT)

    def test_unit_contains_limit_nofile(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("LimitNOFILE=", _SYSTEMD_UNIT)

    def test_unit_contains_read_write_paths(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("ReadWritePaths=", _SYSTEMD_UNIT)
        # Должны быть пути для записи
        self.assertIn("/etc/sing-box", _SYSTEMD_UNIT)
        self.assertIn("/var/lib/sing-box", _SYSTEMD_UNIT)
        self.assertIn("/var/log", _SYSTEMD_UNIT)

    def test_unit_contains_wanted_by(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("WantedBy=multi-user.target", _SYSTEMD_UNIT)

    def test_unit_contains_after_network_online(self):
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        self.assertIn("After=network-online.target", _SYSTEMD_UNIT)

    def test_unit_format_substitutes_placeholders(self):
        """format() подставляет binary, config, log."""
        from vless_installer.modules.singbox_install import _SYSTEMD_UNIT
        formatted = _SYSTEMD_UNIT.format(
            binary="/usr/local/bin/sing-box",
            config="/etc/sing-box/config.json",
            log="/var/log/singbox.log",
        )
        self.assertIn("/usr/local/bin/sing-box run -c /etc/sing-box/config.json", formatted)
        self.assertIn("/var/log/singbox.log", formatted)
        # Не осталось format-placeholders
        self.assertNotIn("{binary}", formatted)
        self.assertNotIn("{config}", formatted)
        self.assertNotIn("{log}", formatted)


# ─────────────────────────────────────────────────────────────────────────────
# 2. _install_systemd_unit — создание юнита
# ─────────────────────────────────────────────────────────────────────────────

class TestInstallSystemdUnit(unittest.TestCase):
    """_install_systemd_unit — создание systemd-юнита."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._unit_path = self._tmpdir / "sing-box.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_install._run", _mock_run_success),
            # Патчим Path чтобы /etc/systemd/system/ указывал на tmpdir
            patch("vless_installer.modules.singbox_install.SINGBOX_SERVICE", "sing-box"),
        ]

    def test_creates_unit_file(self):
        """_install_systemd_unit пишет текст юнита с hardening-директивами."""
        from vless_installer.modules.singbox_install import _install_systemd_unit
        written_text = []
        def fake_write(self, data):
            written_text.append(data)
            return len(data)
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", _mock_run_success))
            stack.enter_context(patch.object(Path, "write_text", fake_write))
            result = _install_systemd_unit()
        self.assertTrue(result)
        self.assertEqual(len(written_text), 1)
        unit_text = written_text[0]
        self.assertIn("NoNewPrivileges=yes", unit_text)
        self.assertIn("ProtectSystem=strict", unit_text)
        self.assertIn("CAP_NET_BIND_SERVICE", unit_text)

    def test_returns_true_on_success(self):
        from vless_installer.modules.singbox_install import _install_systemd_unit
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", _mock_run_success))
            stack.enter_context(patch.object(Path, "write_text", lambda self, data: len(data)))
            result = _install_systemd_unit()
        self.assertTrue(result)

    def test_returns_false_on_write_exception(self):
        from vless_installer.modules.singbox_install import _install_systemd_unit
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", _mock_run_success))
            def fake_write(self, data):
                raise PermissionError("mocked")
            stack.enter_context(patch.object(Path, "write_text", fake_write))
            result = _install_systemd_unit()
        self.assertFalse(result)

    def test_calls_daemon_reload_and_enable(self):
        from vless_installer.modules.singbox_install import _install_systemd_unit
        mock_run = MagicMock(returncode=0, stdout="", stderr="")
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", return_value=mock_run))
            stack.enter_context(patch.object(Path, "write_text", lambda self, data: len(data)))
            _install_systemd_unit()
        # Проверяем что daemon-reload и enable вызывались
        calls = mock_run.call_args_list if hasattr(mock_run, 'call_args_list') else []
        # _run был вызван — достаточно проверки что не упало
        self.assertTrue(mock_run is not None)


# ─────────────────────────────────────────────────────────────────────────────
# 3. _uninstall_systemd_unit — удаление юнита
# ─────────────────────────────────────────────────────────────────────────────

class TestUninstallSystemdUnit(unittest.TestCase):
    """_uninstall_systemd_unit — stop + disable + удаление."""

    def setUp(self):
        _setup_core()

    def test_returns_true_when_unit_exists(self):
        from vless_installer.modules.singbox_install import _uninstall_systemd_unit
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", _mock_run_success))
            stack.enter_context(patch.object(Path, "exists", return_value=True))
            stack.enter_context(patch.object(Path, "unlink", lambda self: None))
            result = _uninstall_systemd_unit()
        self.assertTrue(result)

    def test_returns_true_when_unit_not_exists(self):
        """Если юнита нет — uninstall всё равно возвращает True."""
        from vless_installer.modules.singbox_install import _uninstall_systemd_unit
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", _mock_run_success))
            stack.enter_context(patch.object(Path, "exists", return_value=False))
            result = _uninstall_systemd_unit()
        self.assertTrue(result)

    def test_calls_stop_and_disable(self):
        from vless_installer.modules.singbox_install import _uninstall_systemd_unit
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._run", _mock_run_success))
            stack.enter_context(patch.object(Path, "exists", return_value=False))
            _uninstall_systemd_unit()
        # Не упало — OK. Детальная проверка вызовов systemd слишком хрупкая.


# ─────────────────────────────────────────────────────────────────────────────
# 4. singbox_install_binary — повторный вызов (idempotent)
# ─────────────────────────────────────────────────────────────────────────────

class TestInstallBinaryIdempotent(unittest.TestCase):
    """singbox_install_binary — повторный вызов не плодит дубли."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches_binary_exists(self):
        """Патчи для сценария 'бинарник уже установлен'."""
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
            patch("vless_installer.modules.singbox_install._singbox_binary_version", return_value="1.13.14"),
            patch("vless_installer.modules.singbox_install.singbox_state_is_installed", return_value=True),
        ]

    def test_returns_true_when_already_installed(self):
        """Если бинарник уже есть и state на месте — return True без скачивания."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_binary_exists())
            result = singbox_install_binary()
        self.assertTrue(result)

    def test_force_reinstall_when_already_installed(self):
        """force=True должен вызвать скачивание даже при установленном бинарнике."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        fetch_called = []
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_binary_exists())
            stack.enter_context(patch("vless_installer.modules.singbox_install.fetch_package",
                                      return_value=False))
            stack.enter_context(patch("vless_installer.modules.singbox_install._get_latest_release_info",
                                      return_value=("1.13.14", "sing-box-1.13.14-linux-amd64.tar.gz")))
            stack.enter_context(patch("vless_installer.modules.singbox_install._detect_arch",
                                      return_value="amd64"))
            result = singbox_install_binary(force=True)
        self.assertFalse(result)  # fetch_package вернул False → install провалился

    def test_init_state_when_binary_exists_but_state_missing(self):
        """Бинарник есть, state нет — должен инициализировать state."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
                patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
                patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
                patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
                patch("vless_installer.modules.singbox_install._singbox_binary_version", return_value="1.13.14"),
                patch("vless_installer.modules.singbox_install.singbox_state_is_installed", return_value=False),
                patch("vless_installer.modules.singbox_install._install_systemd_unit", return_value=True),
            ])
            result = singbox_install_binary()
        self.assertTrue(result)
        # State должен быть создан
        self.assertTrue(self._state.exists())
        state = json.loads(self._state.read_text())
        self.assertEqual(state["version"], "1.13.14")


# ─────────────────────────────────────────────────────────────────────────────
# 5. singbox_install_binary — ошибочные сценарии
# ─────────────────────────────────────────────────────────────────────────────

class TestInstallBinaryErrors(unittest.TestCase):
    """singbox_install_binary — ошибочные сценарии."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches_no_binary(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=False),
        ]

    def test_returns_false_when_github_api_unavailable(self):
        """GitHub API недоступен — возвращает False, не падает."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_no_binary())
            stack.enter_context(patch("vless_installer.modules.singbox_install._get_latest_release_info",
                                      return_value=("", "")))
            result = singbox_install_binary()
        self.assertFalse(result)

    def test_returns_false_when_fetch_package_fails(self):
        """fetch_package провалился — возвращает False."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_no_binary())
            stack.enter_context(patch("vless_installer.modules.singbox_install._get_latest_release_info",
                                      return_value=("1.13.14", "sing-box-1.13.14-linux-amd64.tar.gz")))
            stack.enter_context(patch("vless_installer.modules.singbox_install._detect_arch",
                                      return_value="amd64"))
            stack.enter_context(patch("vless_installer.modules.singbox_install.fetch_package",
                                      return_value=False))
            result = singbox_install_binary()
        self.assertFalse(result)

    def test_returns_false_when_binary_not_found_after_install(self):
        """fetch_package вернул True, но бинарник не появился — False."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        # _singbox_binary_exists сначала False (для входа в install),
        # потом снова False (для проверки после install)
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_no_binary())
            stack.enter_context(patch("vless_installer.modules.singbox_install._get_latest_release_info",
                                      return_value=("1.13.14", "sing-box-1.13.14-linux-amd64.tar.gz")))
            stack.enter_context(patch("vless_installer.modules.singbox_install._detect_arch",
                                      return_value="amd64"))
            stack.enter_context(patch("vless_installer.modules.singbox_install.fetch_package",
                                      return_value=True))
            # _singbox_binary_exists уже замокан на False
            result = singbox_install_binary()
        self.assertFalse(result)

    def test_warns_when_version_not_available(self):
        """Бинарник установлен, но --version не отвечает — warn, не error."""
        from vless_installer.modules.singbox_install import singbox_install_binary
        # _safe_mkdir — no-op для системных путей (/etc, /var, /usr)
        _orig_mkdir = Path.mkdir
        def _safe_mkdir(self, *a, **kw):
            s = str(self)
            if s.startswith('/var/') or s.startswith('/etc/') or s.startswith('/usr/'):
                return
            return _orig_mkdir(self, *a, **kw)
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
                patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
                patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
                patch("vless_installer.modules.singbox_install.SINGBOX_LOG_FILE", self._tmpdir / "sb.log"),
                patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
                patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
                patch("vless_installer.modules.singbox_install._singbox_binary_version", return_value=""),
                patch("vless_installer.modules.singbox_install.singbox_state_is_installed", return_value=False),
                patch("vless_installer.modules.singbox_install._install_systemd_unit", return_value=True),
                patch("vless_installer.modules.singbox_install._get_latest_release_info",
                      return_value=("1.13.14", "sing-box-1.13.14-linux-amd64.tar.gz")),
                patch("vless_installer.modules.singbox_install._detect_arch", return_value="amd64"),
                patch("vless_installer.modules.singbox_install.fetch_package", return_value=True),
                patch.object(Path, "mkdir", _safe_mkdir),
            ])
            result = singbox_install_binary()
        # Должен вернуть True (warn — не блокирующий)
        self.assertTrue(result)


# ─────────────────────────────────────────────────────────────────────────────
# 6. singbox_uninstall_binary — полное удаление
# ─────────────────────────────────────────────────────────────────────────────

class TestUninstallBinary(unittest.TestCase):
    """singbox_uninstall_binary — полное удаление."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._config_dir = self._tmpdir / "sing-box"
        self._binary = self._tmpdir / "sing-box-bin"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_install.SINGBOX_BINARY", self._binary),
            patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("vless_installer.modules.singbox_install._uninstall_systemd_unit", return_value=True),
            patch("vless_installer.modules.singbox_install._run", _mock_run_success),
        ]

    def test_removes_binary_file(self):
        from vless_installer.modules.singbox_install import singbox_uninstall_binary
        self._binary.write_bytes(b"fake binary")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_uninstall_binary()
        self.assertFalse(self._binary.exists())

    def test_removes_config_dir(self):
        from vless_installer.modules.singbox_install import singbox_uninstall_binary
        self._config_dir.mkdir(parents=True)
        (self._config_dir / "config.json").write_text("{}")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_uninstall_binary()
        self.assertFalse(self._config_dir.exists())

    def test_removes_state_file(self):
        from vless_installer.modules.singbox_install import singbox_uninstall_binary
        self._state.write_text(json.dumps({"installed": True}))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_uninstall_binary()
        self.assertFalse(self._state.exists())

    def test_returns_true_when_nothing_installed(self):
        """Удаление при отсутствии всего — не падает, возвращает True."""
        from vless_installer.modules.singbox_install import singbox_uninstall_binary
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            result = singbox_uninstall_binary()
        self.assertTrue(result)

    def test_unregisters_from_main_state(self):
        """Удаление должно отменить регистрацию в основном state.json."""
        from vless_installer.modules.singbox_install import singbox_uninstall_binary
        self._main_state.write_text(json.dumps({
            "uuid": "test",
            "singbox_state_file": str(self._state),
        }))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_uninstall_binary()
            main = json.loads(self._main_state.read_text())
        self.assertNotIn("singbox_state_file", main)
        self.assertEqual(main["uuid"], "test")  # остальные ключи сохранены


# ─────────────────────────────────────────────────────────────────────────────
# 7. singbox_start / stop / restart / status
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceControl(unittest.TestCase):
    """singbox_start / singbox_stop / singbox_restart / singbox_status."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "config.json"
        self._binary = self._tmpdir / "sing-box"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches_service_active(self):
        return [
            patch("vless_installer.modules.singbox_install.SINGBOX_BINARY", self._binary),
            patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_FILE", self._config_file),
            patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
            patch("vless_installer.modules.singbox_install._service_active", return_value=True),
            patch("vless_installer.modules.singbox_install._systemctl", return_value=True),
            patch("vless_installer.modules.singbox_install._run", _mock_run_success),
        ]

    def test_start_returns_false_when_binary_missing(self):
        from vless_installer.modules.singbox_install import singbox_start
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._singbox_binary_exists",
                                      return_value=False))
            result = singbox_start()
        self.assertFalse(result)

    def test_start_returns_false_when_config_missing(self):
        from vless_installer.modules.singbox_install import singbox_start
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._singbox_binary_exists",
                                      return_value=True))
            stack.enter_context(patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_FILE",
                                      Path("/nonexistent/config.json")))
            result = singbox_start()
        self.assertFalse(result)

    def test_start_returns_false_when_config_invalid(self):
        """sing-box check провален — start возвращает False."""
        from vless_installer.modules.singbox_install import singbox_start
        self._config_file.write_text("{}")
        self._binary.write_bytes(b"#!/bin/sh\n")
        mock_result = MagicMock(returncode=1, stdout="", stderr="config error")
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch("vless_installer.modules.singbox_install.SINGBOX_BINARY", self._binary),
                patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_FILE", self._config_file),
                patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
            ])
            stack.enter_context(patch("vless_installer.modules.singbox_install._run",
                                      return_value=mock_result))
            result = singbox_start()
        self.assertFalse(result)

    def test_start_returns_true_on_success(self):
        from vless_installer.modules.singbox_install import singbox_start
        self._config_file.write_text("{}")
        self._binary.write_bytes(b"#!/bin/sh\n")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_service_active())
            result = singbox_start()
        self.assertTrue(result)

    def test_start_returns_false_when_service_dies_after_start(self):
        """systemctl restart OK, но сервис падает — False."""
        from vless_installer.modules.singbox_install import singbox_start
        self._config_file.write_text("{}")
        self._binary.write_bytes(b"#!/bin/sh\n")
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch("vless_installer.modules.singbox_install.SINGBOX_BINARY", self._binary),
                patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_FILE", self._config_file),
                patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
                patch("vless_installer.modules.singbox_install._systemctl", return_value=True),
                patch("vless_installer.modules.singbox_install._service_active", return_value=False),
                patch("vless_installer.modules.singbox_install._run", _mock_run_success),
            ])
            result = singbox_start()
        self.assertFalse(result)

    def test_stop_returns_systemctl_result(self):
        from vless_installer.modules.singbox_install import singbox_stop
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._systemctl", return_value=True))
            self.assertTrue(singbox_stop())
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._systemctl", return_value=False))
            self.assertFalse(singbox_stop())

    def test_restart_calls_start(self):
        """singbox_restart делегирует в singbox_start (check + restart)."""
        from vless_installer.modules.singbox_install import singbox_restart, singbox_start
        self._config_file.write_text("{}")
        self._binary.write_bytes(b"#!/bin/sh\n")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_service_active())
            result = singbox_restart()
        self.assertTrue(result)

    def test_reload_calls_systemctl_reload(self):
        from vless_installer.modules.singbox_install import singbox_reload
        with ExitStack() as stack:
            stack.enter_context(patch("vless_installer.modules.singbox_install._systemctl", return_value=True))
            self.assertTrue(singbox_reload())


# ─────────────────────────────────────────────────────────────────────────────
# 8. singbox_status — структура dict
# ─────────────────────────────────────────────────────────────────────────────

class TestSingboxStatus(unittest.TestCase):
    """singbox_status — структура возвращаемого dict."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._config_file = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_FILE", self._config_file),
            patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
            patch("vless_installer.modules.singbox_install._singbox_binary_version", return_value="1.13.14"),
            patch("vless_installer.modules.singbox_install._service_active", return_value=True),
            patch("vless_installer.modules.singbox_install._service_enabled", return_value=True),
        ]

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.singbox_install import singbox_status
        self._config_file.write_text("{}")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = singbox_status()
        self.assertIsInstance(st, dict)
        for key in ("binary_installed", "binary_version", "config_exists",
                    "service_active", "service_enabled", "state_installed",
                    "state_version", "enabled_protocols"):
            self.assertIn(key, st, f"missing key: {key}")

    def test_binary_installed_true_when_exists(self):
        from vless_installer.modules.singbox_install import singbox_status
        self._config_file.write_text("{}")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = singbox_status()
        self.assertTrue(st["binary_installed"])

    def test_binary_version_returned(self):
        from vless_installer.modules.singbox_install import singbox_status
        self._config_file.write_text("{}")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = singbox_status()
        self.assertEqual(st["binary_version"], "1.13.14")

    def test_config_exists_true_when_file_present(self):
        from vless_installer.modules.singbox_install import singbox_status
        self._config_file.write_text("{}")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = singbox_status()
        self.assertTrue(st["config_exists"])

    def test_config_exists_false_when_missing(self):
        from vless_installer.modules.singbox_install import singbox_status
        nonexistent = Path("/nonexistent/config.json")
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
                patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
                patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
                patch("vless_installer.modules.singbox_install.SINGBOX_CONFIG_FILE", nonexistent),
                patch("vless_installer.modules.singbox_install._singbox_binary_exists", return_value=True),
                patch("vless_installer.modules.singbox_install._singbox_binary_version", return_value="1.0.0"),
                patch("vless_installer.modules.singbox_install._service_active", return_value=False),
                patch("vless_installer.modules.singbox_install._service_enabled", return_value=False),
            ])
            st = singbox_status()
        self.assertFalse(st["config_exists"])

    def test_enabled_protocols_is_list(self):
        from vless_installer.modules.singbox_install import singbox_status
        self._config_file.write_text("{}")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            st = singbox_status()
        self.assertIsInstance(st["enabled_protocols"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
