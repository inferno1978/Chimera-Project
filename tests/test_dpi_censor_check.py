#!/usr/bin/env python3
"""
tests/test_dpi_censor_check.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dpi_censor_check.py.

Покрывает:
  1. _deps_missing — проверка отсутствующих Python-модулей
  2. _build_args — сборка CLI аргументов
  3. _REQUIRED_MODULES — список зависимостей
  4. v77 — автообновление апстрима Runnin4ik/dpi-detector:
     • _version_key — семвер-ключ (числа как числа, v-префикс, rc-суффиксы)
     • _parse_entry_version / _vendor_version — версия с диска
     • _installed_copy — активная копия = новейшая из (вендорная, runtime)
     • _fetch_latest_lsremote — парсинг git ls-remote (4.0.10 > 4.0.9!)
     • _latest_upstream_version — кэш (TTL успеха/неудачи, force, фолбэк)
     • _update_available / _version_rows / _update_item_label — UI-логика
     • _download_and_install — runtime-установка без git-дерева,
       исключения images/Docker/CI, чистка старых версий, state
     • do_dpi_censor_check_menu — шапка с версиями, [4], предложение
       обновиться перед запуском, запуск активной копии
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


def _mod():
    """Импорт модуля с подменённым _core (как в остальных тестах)."""
    _setup_core_in_sysmodules()
    import chimera.modules.dpi_censor_check as m
    return m


def _make_vendor(root: Path, version: str = "3.3.0",
                 with_version_line: bool = True) -> Path:
    """Фейковая вендорная копия в tmp."""
    vendor = root / "vendor"
    vendor.mkdir(parents=True, exist_ok=True)
    entry = vendor / "dpi_detector.py"
    entry.write_text(
        f'CURRENT_VERSION = "{version}"\n' if with_version_line else "# no version\n"
    )
    (vendor / "requirements.txt").write_text("httpx\nrich\nPyYAML\n")
    (vendor / "VENDOR_INFO.md").write_text(
        f"# vendor info\n\n| Версия | v{version} |\n| Commit | dead00 |\n"
    )
    return vendor


def _make_runtime(root: Path, version: str,
                  with_entry: bool = True) -> Path:
    """Фейковая runtime-копия в tmp (каталог-имя = версия)."""
    rt = root / "rt" / version
    rt.mkdir(parents=True, exist_ok=True)
    if with_entry:
        (rt / "dpi_detector.py").write_text(f'CURRENT_VERSION = "{version}"\n')
        (rt / "requirements.txt").write_text("httpx\n")
    return rt


def _make_fake_upstream(dest: Path, version: str) -> Path:
    """Фейковый распакованный tarball апстрима в dest. Возвращает корень."""
    root = dest / f"dpi-detector-{version}"
    (root / "cli").mkdir(parents=True, exist_ok=True)
    (root / "cli" / "__init__.py").write_text("")
    (root / "cli" / "runners.py").write_text("# runners\n")
    (root / "utils").mkdir(exist_ok=True)
    (root / "utils" / "__init__.py").write_text("")
    (root / "core").mkdir(exist_ok=True)
    (root / "core" / "__init__.py").write_text("")
    (root / "dpi_detector.py").write_text(f'CURRENT_VERSION = "{version}"\n')
    (root / "requirements.txt").write_text("httpx>=0.28.1\nrich>=14\n")
    (root / "config.yml").write_text("x: 1\n")
    (root / "domains.txt").write_text("# domains\n")
    (root / "tcp16.json").write_text("[]")
    (root / "whitelist_sni.txt").write_text("")
    (root / "LICENSE").write_text("MIT")
    (root / "README.md").write_text("readme")
    # Мусор, который копировать НЕ должны (как в вендоринге):
    (root / "images").mkdir(exist_ok=True)
    (root / "images" / "logo.jpg").write_bytes(b"\0" * 16)
    (root / ".github").mkdir(exist_ok=True)
    (root / ".github" / "workflows").mkdir(exist_ok=True)
    (root / "Dockerfile").write_text("FROM scratch\n")
    (root / "Dockerfile.web").write_text("FROM scratch\n")
    (root / "docker-compose.yml").write_text("services: {}\n")
    (root / ".gitignore").write_text("*.pyc\n")
    return root


# ══════════════════════════════════════════════════════════════════════════
#  Прежние тесты (зависимости, CLI-аргументы)
# ══════════════════════════════════════════════════════════════════════════

class TestRequiredModules(unittest.TestCase):
    """_REQUIRED_MODULES — список."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_httpx_rich_yaml(self):
        from chimera.modules.dpi_censor_check import _REQUIRED_MODULES
        for mod in ("httpx", "rich", "yaml"):
            self.assertIn(mod, _REQUIRED_MODULES)


class TestDepsMissing(unittest.TestCase):
    """_deps_missing — проверка отсутствующих модулей."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_all_present(self):
        from chimera.modules.dpi_censor_check import _deps_missing
        with patch("importlib.util.find_spec", return_value=MagicMock()):
            self.assertEqual(_deps_missing(), [])

    def test_returns_missing_modules(self):
        from chimera.modules.dpi_censor_check import (
            _deps_missing, _REQUIRED_MODULES,
        )
        with patch("importlib.util.find_spec", return_value=None):
            result = _deps_missing()
        for mod in _REQUIRED_MODULES:
            self.assertIn(mod, result)

    def test_partial_missing(self):
        from chimera.modules.dpi_censor_check import _deps_missing
        def _fake_find(mod):
            return MagicMock() if mod == "httpx" else None
        with patch("importlib.util.find_spec", side_effect=_fake_find):
            result = _deps_missing()
        self.assertNotIn("httpx", result)
        self.assertIn("rich", result)
        self.assertIn("yaml", result)


class TestBuildArgs(unittest.TestCase):
    """_build_args — pure CLI args builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_all_none_returns_empty(self):
        from chimera.modules.dpi_censor_check import _build_args
        self.assertEqual(_build_args(None, None, None), [])

    def test_domains_only(self):
        from chimera.modules.dpi_censor_check import _build_args
        result = _build_args(["a.com", "b.com"], None, None)
        self.assertEqual(result, ["-d", "a.com", "-d", "b.com"])

    def test_proxy_only(self):
        from chimera.modules.dpi_censor_check import _build_args
        result = _build_args(None, "socks5://127.0.0.1:1080", None)
        self.assertEqual(result, ["-p", "socks5://127.0.0.1:1080"])

    def test_output_only(self):
        from chimera.modules.dpi_censor_check import _build_args
        result = _build_args(None, None, "/tmp/report.json")
        self.assertEqual(result, ["-o", "/tmp/report.json"])

    def test_all_combined(self):
        from chimera.modules.dpi_censor_check import _build_args
        result = _build_args(["x.com"], "proxy", "out.json")
        self.assertIn("-d", result)
        self.assertIn("x.com", result)
        self.assertIn("-p", result)
        self.assertIn("proxy", result)
        self.assertIn("-o", result)
        self.assertIn("out.json", result)

    def test_empty_domains_list(self):
        from chimera.modules.dpi_censor_check import _build_args
        result = _build_args([], None, None)
        self.assertEqual(result, [])


# ══════════════════════════════════════════════════════════════════════════
#  v77: версии
# ══════════════════════════════════════════════════════════════════════════

class TestVersionKey(unittest.TestCase):
    """_version_key — семвер-ключ: числа как ЧИСЛА (4.0.10 > 4.0.9)."""

    def setUp(self):
        self.m = _mod()

    def test_numbers_not_strings(self):
        # "4.0.10" > "4.0.9" > "4.0.3" — строкой было бы наоборот
        self.assertGreater(self.m._version_key("4.0.10"), self.m._version_key("4.0.9"))
        self.assertGreater(self.m._version_key("4.0.9"), self.m._version_key("4.0.3"))

    def test_v_prefix_ignored(self):
        self.assertEqual(self.m._version_key("v4.1.0"), self.m._version_key("4.1.0"))
        self.assertEqual(self.m._version_key("V4.1.0"), self.m._version_key("4.1.0"))

    def test_major_minor(self):
        self.assertGreater(self.m._version_key("4.1.0"), self.m._version_key("4.0.18"))
        self.assertGreater(self.m._version_key("3.4.0"), self.m._version_key("3.3.0"))

    def test_rc_lower_than_release(self):
        self.assertLess(self.m._version_key("4.1.0rc1"), self.m._version_key("4.1.0"))
        self.assertLess(self.m._version_key("4.1.0-beta2"), self.m._version_key("4.1.0"))

    def test_longer_number_tuple_newer(self):
        self.assertGreater(self.m._version_key("4.1"), self.m._version_key("4.0.9"))
        self.assertGreater(self.m._version_key("4.1.0.1"), self.m._version_key("4.1.0"))

    def test_garbage_and_empty_sort_lowest(self):
        for bad in ("", None, "мусор", "abc", "v"):
            self.assertLess(self.m._version_key(bad), self.m._version_key("0.0.1"))

    def test_real_upstream_tags_chain(self):
        # Реальная история тегов апстрима (подряд): 3.3.0 < 3.4.0 < 4.0.0
        # < 4.0.3 < 4.0.4 < 4.0.10 < 4.0.11 < 4.0.18 = 4.1.0
        chain = ["3.3.0", "3.4.0", "4.0.0", "4.0.3", "4.0.4",
                 "4.0.10", "4.0.11", "4.0.18", "4.1.0"]
        keys = [self.m._version_key(t) for t in chain]
        self.assertEqual(keys, sorted(keys))


class TestParseEntryVersion(unittest.TestCase):
    """_parse_entry_version — версия читается с диска (факт, не state)."""

    def setUp(self):
        self.m = _mod()
        self.tmp = Path(tempfile.mkdtemp())

    def test_reads_current_version(self):
        f = self.tmp / "dpi_detector.py"
        f.write_text('import os\nCURRENT_VERSION = "4.1.0"\n')
        self.assertEqual(self.m._parse_entry_version(f), "4.1.0")

    def test_v_prefix_stripped(self):
        f = self.tmp / "dpi_detector.py"
        f.write_text("CURRENT_VERSION = 'v4.1.0'")
        self.assertEqual(self.m._parse_entry_version(f), "4.1.0")

    def test_no_match_returns_empty(self):
        f = self.tmp / "dpi_detector.py"
        f.write_text("# нет версии")
        self.assertEqual(self.m._parse_entry_version(f), "")

    def test_missing_file_returns_empty(self):
        self.assertEqual(self.m._parse_entry_version(self.tmp / "nope.py"), "")


class TestInstalledCopy(unittest.TestCase):
    """_installed_copy — активная копия = новейшая из (вендорная, runtime)."""

    def setUp(self):
        self.m = _mod()
        self.tmp = Path(tempfile.mkdtemp())
        self.vendor = _make_vendor(self.tmp, "3.3.0")
        self.rt_root = self.tmp / "rt"

    def _patched(self):
        return [
            patch.object(self.m, "_VENDOR_DIR", self.vendor),
            patch.object(self.m, "_ENTRY", self.vendor / "dpi_detector.py"),
            patch.object(self.m, "_REQS", self.vendor / "requirements.txt"),
            patch.object(self.m, "_RUNTIME_ROOT", self.rt_root),
        ]

    def test_only_vendor(self):
        patches = self._patched()
        for p in patches:
            p.start()
        try:
            copy = self.m._installed_copy()
            self.assertEqual(copy["version"], "3.3.0")
            self.assertEqual(copy["source"], "vendor")
            self.assertEqual(copy["entry"], self.vendor / "dpi_detector.py")
        finally:
            for p in patches:
                p.stop()

    def test_runtime_newer_wins(self):
        _make_runtime(self.tmp, "4.1.0")
        patches = self._patched()
        for p in patches:
            p.start()
        try:
            copy = self.m._installed_copy()
            self.assertEqual(copy["version"], "4.1.0")
            self.assertEqual(copy["source"], "runtime")
            self.assertEqual(copy["entry"], self.rt_root / "4.1.0" / "dpi_detector.py")
        finally:
            for p in patches:
                p.stop()

    def test_vendor_newer_than_runtime(self):
        _make_runtime(self.tmp, "3.0.0")
        patches = self._patched()
        for p in patches:
            p.start()
        try:
            copy = self.m._installed_copy()
            self.assertEqual(copy["source"], "vendor")
            self.assertEqual(copy["version"], "3.3.0")
        finally:
            for p in patches:
                p.stop()

    def test_runtime_without_entry_skipped(self):
        _make_runtime(self.tmp, "9.9.9", with_entry=False)
        patches = self._patched()
        for p in patches:
            p.start()
        try:
            copy = self.m._installed_copy()
            self.assertEqual(copy["source"], "vendor")
        finally:
            for p in patches:
                p.stop()

    def test_staging_dirs_ignored(self):
        st = self.rt_root / ".staging-9.9.9"
        st.mkdir(parents=True)
        (st / "dpi_detector.py").write_text('CURRENT_VERSION = "9.9.9"\n')
        patches = self._patched()
        for p in patches:
            p.start()
        try:
            copy = self.m._installed_copy()
            self.assertEqual(copy["source"], "vendor")
        finally:
            for p in patches:
                p.stop()

    def test_nothing_installed(self):
        with patch.object(self.m, "_ENTRY", self.tmp / "missing.py"), \
             patch.object(self.m, "_RUNTIME_ROOT", self.tmp / "nope-rt"):
            self.assertEqual(self.m._installed_copy(), {})

    def test_vendor_info_fallback_when_entry_has_no_version(self):
        vendor2 = _make_vendor(self.tmp / "v2", "5.5.5", with_version_line=False)
        # entry без CURRENT_VERSION, но VENDOR_INFO.md знает версию
        with patch.object(self.m, "_VENDOR_DIR", vendor2), \
             patch.object(self.m, "_ENTRY", vendor2 / "dpi_detector.py"), \
             patch.object(self.m, "_RUNTIME_ROOT", self.tmp / "nope-rt"):
            self.assertEqual(self.m._vendor_version(), "5.5.5")

    def test_active_entry_and_reqs_follow_active_copy(self):
        _make_runtime(self.tmp, "4.1.0")
        patches = self._patched()
        for p in patches:
            p.start()
        try:
            self.assertEqual(self.m._active_entry(),
                             self.rt_root / "4.1.0" / "dpi_detector.py")
            self.assertEqual(self.m._active_reqs(),
                             self.rt_root / "4.1.0" / "requirements.txt")
        finally:
            for p in patches:
                p.stop()


# ══════════════════════════════════════════════════════════════════════════
#  v77: последняя версия на GitHub
# ══════════════════════════════════════════════════════════════════════════

class TestFetchLatestLsremote(unittest.TestCase):
    """_fetch_latest_lsremote — парсинг вывода git ls-remote --tags."""

    def setUp(self):
        self.m = _mod()

    def _fake_run(self, stdout: str):
        r = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        return patch.object(self.m.subprocess, "run", return_value=r)

    def test_numeric_max_with_double_digit_patch(self):
        out = (
            "39828ee39330147c1e4ce56572beae68a3c83e9b\trefs/tags/v3.4.0\n"
            "823640a3f1fde59ced29e5ef83a86ef119d29abd\trefs/tags/v4.1.0\n"
            "823640a3f1fde59ced29e5ef83a86ef119d29abd\trefs/tags/v4.1.0^{}\n"
            "fa2301e1d85b9c49159ea862f1dfedf09d1577e2\trefs/tags/v4.0.10\n"
            "1aa284cce76efed753418c0364fddb896ebf18af\trefs/tags/v4.0.3\n"
        )
        with self._fake_run(out):
            self.assertEqual(self.m._fetch_latest_lsremote(), "4.1.0")

    def test_no_tags_returns_empty(self):
        with self._fake_run(""):
            self.assertEqual(self.m._fetch_latest_lsremote(), "")

    def test_garbage_lines_ignored(self):
        out = "xxx\trefs/heads/main\nyyy\tnot-a-ref\n"
        with self._fake_run(out):
            self.assertEqual(self.m._fetch_latest_lsremote(), "")

    def test_nonzero_exit_returns_empty(self):
        r = SimpleNamespace(returncode=128, stdout="", stderr="fatal")
        with patch.object(self.m.subprocess, "run", return_value=r):
            self.assertEqual(self.m._fetch_latest_lsremote(), "")


class TestLatestUpstreamVersion(unittest.TestCase):
    """_latest_upstream_version — кэш: TTL успеха/неудачи, force, фолбэк."""

    def setUp(self):
        self.m = _mod()
        self.tmp = Path(tempfile.mkdtemp())
        self.state = self.tmp / "dpi_censor_check.json"

    def test_api_success_cached(self):
        api = MagicMock(return_value="4.1.0")
        ls = MagicMock(return_value="")
        with patch.object(self.m, "_fetch_latest_api", api), \
             patch.object(self.m, "_fetch_latest_lsremote", ls), \
             patch.object(self.m, "_STATE_FILE", self.state):
            first = self.m._latest_upstream_version()
            second = self.m._latest_upstream_version()
        self.assertEqual(first, "4.1.0")
        self.assertEqual(second, "4.1.0")
        # успешная проверка закэширована — сеть дёргалась один раз
        self.assertEqual(api.call_count, 1)
        self.assertEqual(ls.call_count, 0)

    def test_fallback_to_lsremote_when_api_dead(self):
        api = patch.object(self.m, "_fetch_latest_api", return_value="")
        ls = patch.object(self.m, "_fetch_latest_lsremote", return_value="4.0.18")
        with api, ls, patch.object(self.m, "_STATE_FILE", self.state):
            self.assertEqual(self.m._latest_upstream_version(), "4.0.18")

    def test_failure_cached_with_retry_ttl(self):
        api = MagicMock(return_value="")
        ls = MagicMock(return_value="")
        with patch.object(self.m, "_fetch_latest_api", api), \
             patch.object(self.m, "_fetch_latest_lsremote", ls), \
             patch.object(self.m, "_STATE_FILE", self.state):
            self.assertEqual(self.m._latest_upstream_version(), "")
            self.assertEqual(self.m._latest_upstream_version(), "")
        # неудача закэширована — повторные вызовы не дёргают сеть
        self.assertEqual(api.call_count, 1)
        self.assertEqual(ls.call_count, 1)

    def test_force_bypasses_cache(self):
        state = {"latest_check": {"latest": "3.9.9", "checked_at": int(time.time()),
                                  "ok": True}}
        self.state.write_text(json.dumps(state))
        api = MagicMock(return_value="4.1.0")
        with patch.object(self.m, "_fetch_latest_api", api), \
             patch.object(self.m, "_STATE_FILE", self.state):
            self.assertEqual(self.m._latest_upstream_version(force=True), "4.1.0")
        self.assertEqual(api.call_count, 1)

    def test_fresh_cache_no_network(self):
        state = {"latest_check": {"latest": "4.0.18", "checked_at": int(time.time()),
                                  "ok": True}}
        self.state.write_text(json.dumps(state))
        api = MagicMock(return_value="should-not-be-called")
        with patch.object(self.m, "_fetch_latest_api", api), \
             patch.object(self.m, "_STATE_FILE", self.state):
            self.assertEqual(self.m._latest_upstream_version(), "4.0.18")
        self.assertEqual(api.call_count, 0)

    def test_state_written_after_check(self):
        api = patch.object(self.m, "_fetch_latest_api", return_value="4.1.0")
        with api, patch.object(self.m, "_STATE_FILE", self.state):
            self.m._latest_upstream_version()
        data = json.loads(self.state.read_text())
        self.assertEqual(data["latest_check"]["latest"], "4.1.0")
        self.assertTrue(data["latest_check"]["ok"])
        self.assertGreater(data["latest_check"]["checked_at"], 0)

    def test_corrupt_state_ignored(self):
        self.state.write_text("{ not json")
        api = patch.object(self.m, "_fetch_latest_api", return_value="4.1.0")
        with api, patch.object(self.m, "_STATE_FILE", self.state):
            self.assertEqual(self.m._latest_upstream_version(), "4.1.0")


class TestUpdateAvailable(unittest.TestCase):
    """_update_available — только строго новее."""

    def setUp(self):
        self.m = _mod()

    def test_newer(self):
        self.assertEqual(self.m._update_available("3.3.0", "4.1.0"), "4.1.0")

    def test_equal(self):
        self.assertEqual(self.m._update_available("4.1.0", "4.1.0"), "")

    def test_older(self):
        self.assertEqual(self.m._update_available("4.1.0", "3.3.0"), "")

    def test_numeric_not_string(self):
        self.assertEqual(self.m._update_available("4.0.9", "4.0.10"), "4.0.10")

    def test_empty_inputs(self):
        self.assertEqual(self.m._update_available("", "4.1.0"), "")
        self.assertEqual(self.m._update_available("3.3.0", ""), "")
        self.assertEqual(self.m._update_available("", ""), "")


# ══════════════════════════════════════════════════════════════════════════
#  v77: скачивание и установка runtime-копии
# ══════════════════════════════════════════════════════════════════════════

class TestDownloadAndInstall(unittest.TestCase):
    """_download_and_install — runtime-установка (git-дерево не трогаем)."""

    def setUp(self):
        self.m = _mod()
        self.tmp = Path(tempfile.mkdtemp())
        self.rt_root = self.tmp / "rt"
        self.state = self.tmp / "state.json"

    def _run_install(self, version: str, tarball_version: str):
        """Патчит сеть/распаковку; tarball_version — что «в архиве»."""
        dl = patch.object(self.m, "_download_tarball", return_value=True)

        def fake_extract(tar_path, dest_dir):
            return _make_fake_upstream(Path(dest_dir), tarball_version)

        ex = patch.object(self.m, "_extract_tarball", side_effect=fake_extract)
        with dl, ex, patch.object(self.m, "_RUNTIME_ROOT", self.rt_root), \
             patch.object(self.m, "_STATE_FILE", self.state):
            return self.m._download_and_install(version)

    def test_success(self):
        ok, msg = self._run_install("4.1.0", "4.1.0")
        self.assertTrue(ok, msg)
        final = self.rt_root / "4.1.0"
        self.assertTrue((final / "dpi_detector.py").is_file())
        self.assertTrue((final / "cli" / "runners.py").is_file())
        self.assertTrue((final / "requirements.txt").is_file())
        # исключения из вендоринга — не копируются:
        for bad in ("images", ".github", "Dockerfile", "Dockerfile.web",
                    "docker-compose.yml", ".gitignore"):
            self.assertFalse((final / bad).exists(), f"не должно быть {bad}")
        # staging убран:
        self.assertFalse(list(self.rt_root.glob(".staging-*")))
        # state обновлён:
        data = json.loads(self.state.read_text())
        self.assertEqual(data["installed_version"], "4.1.0")
        self.assertEqual(data["installed_dir"], str(final))

    def test_version_mismatch_aborts(self):
        ok, msg = self._run_install("4.1.0", "3.9.9")
        self.assertFalse(ok)
        self.assertIn("3.9.9", msg)
        self.assertFalse((self.rt_root / "4.1.0").exists())
        self.assertFalse(list(self.rt_root.glob(".staging-*")))

    def test_download_failure_aborts(self):
        dl = patch.object(self.m, "_download_tarball", return_value=False)
        with dl, patch.object(self.m, "_RUNTIME_ROOT", self.rt_root), \
             patch.object(self.m, "_STATE_FILE", self.state):
            ok, msg = self.m._download_and_install("4.1.0")
        self.assertFalse(ok)
        self.assertFalse(self.rt_root.exists())

    def test_prunes_old_versions_and_staging_junk(self):
        old = _make_runtime(self.tmp, "3.4.0")
        junk = self.rt_root / ".staging-old"
        junk.mkdir(parents=True)
        ok, msg = self._run_install("4.1.0", "4.1.0")
        self.assertTrue(ok, msg)
        self.assertFalse(old.exists())
        self.assertFalse(junk.exists())
        self.assertTrue((self.rt_root / "4.1.0").is_dir())

    def test_keeps_non_version_dirs_untouched(self):
        stranger = self.rt_root / "my-notes"
        stranger.mkdir(parents=True)
        (stranger / "notes.txt").write_text("не трогай")
        ok, msg = self._run_install("4.1.0", "4.1.0")
        self.assertTrue(ok, msg)
        self.assertTrue((stranger / "notes.txt").exists())

    def test_empty_version_rejected(self):
        ok, msg = self.m._download_and_install("")
        self.assertFalse(ok)

    def test_v_prefix_normalized(self):
        ok, msg = self._run_install("v4.1.0", "4.1.0")
        self.assertTrue(ok, msg)
        self.assertTrue((self.rt_root / "4.1.0" / "dpi_detector.py").is_file())

    def test_vendor_dir_never_touched(self):
        # Настоящая вендорная директория репо не должна измениться:
        before = sorted(p.name for p in self.m._VENDOR_DIR.iterdir())
        self._run_install("4.1.0", "4.1.0")
        after = sorted(p.name for p in self.m._VENDOR_DIR.iterdir())
        self.assertEqual(before, after)


class TestPruneRuntime(unittest.TestCase):
    """_prune_runtime — чистка старых версий и staging-мусора."""

    def setUp(self):
        self.m = _mod()
        self.tmp = Path(tempfile.mkdtemp())
        self.rt_root = self.tmp / "rt"

    def test_prunes_versions_and_staging_keeps_other(self):
        keep = self.rt_root / "4.1.0"
        keep.mkdir(parents=True)
        for name in ("3.4.0", "v3.5.0", ".staging-junk", "9.9.9"):
            (self.rt_root / name).mkdir(parents=True)
        notes = self.rt_root / "readme.txt"
        notes.write_text("x")
        # файл, не каталог:
        (self.rt_root / "4.2.0").write_text("файл-обманка")
        with patch.object(self.m, "_RUNTIME_ROOT", self.rt_root):
            self.m._prune_runtime(keep=keep)
        self.assertTrue(keep.is_dir())
        self.assertTrue(notes.exists())
        self.assertTrue((self.rt_root / "4.2.0").exists())  # файл не трогаем
        for name in ("3.4.0", "v3.5.0", ".staging-junk", "9.9.9"):
            self.assertFalse((self.rt_root / name).exists(), name)

    def test_missing_root_noop(self):
        with patch.object(self.m, "_RUNTIME_ROOT", self.tmp / "nope"):
            self.m._prune_runtime(keep=self.tmp / "nope" / "1.0.0")


# ══════════════════════════════════════════════════════════════════════════
#  v77: UI — шапка меню, пункт [4], предложение перед запуском
# ══════════════════════════════════════════════════════════════════════════

class TestVersionRows(unittest.TestCase):
    """_version_rows — строки шапки (влезают в 64 колонки)."""

    def setUp(self):
        self.m = _mod()

    def test_update_available(self):
        ver, upd, kind = self.m._version_rows("3.3.0", "vendor", "4.1.0")
        self.assertIn("3.3.0", ver)
        self.assertIn("вендорная копия", ver)
        self.assertIn("v4.1.0", upd)
        self.assertIn("[4]", upd)
        self.assertEqual(kind, "yellow")

    def test_up_to_date(self):
        _, upd, kind = self.m._version_rows("4.1.0", "runtime", "4.1.0")
        self.assertIn("последняя", upd)
        self.assertEqual(kind, "green")

    def test_not_checked(self):
        _, upd, kind = self.m._version_rows("3.3.0", "vendor", "")
        self.assertIn("не проверено", upd)
        self.assertEqual(kind, "dim")

    def test_runtime_source_labeled(self):
        ver, _, _ = self.m._version_rows("4.1.0", "runtime", "")
        self.assertIn("авто-обновление", ver)

    def test_rows_fit_64_columns(self):
        for installed, source, latest in (
            ("3.3.0", "vendor", "4.1.0"),
            ("4.1.0", "runtime", "4.1.0"),
            ("3.3.0", "vendor", ""),
            ("10.11.12", "vendor", "10.11.13"),
        ):
            ver, upd, _ = self.m._version_rows(installed, source, latest)
            self.assertLessEqual(len(ver), 64, ver)
            self.assertLessEqual(len(upd), 64, upd)

    def test_item_labels_fit_and_informative(self):
        with_upd = self.m._update_item_label("4.1.0", "3.3.0")
        self.assertIn("v4.1.0", with_upd)
        self.assertIn("Обновить", with_upd)
        fresh = self.m._update_item_label("4.1.0", "4.1.0")
        self.assertIn("Проверить", fresh)
        unknown = self.m._update_item_label("", "3.3.0")
        self.assertIn("Проверить", unknown)
        for label in (with_upd, fresh, unknown):
            # «  [4]  » + label в рамке 64 колонки
            self.assertLessEqual(len(label), 55, label)


class TestMenuFlow(unittest.TestCase):
    """do_dpi_censor_check_menu — шапка, [4], обновление перед запуском."""

    def setUp(self):
        self.m = _mod()
        self.tmp = Path(tempfile.mkdtemp())
        self.vendor = _make_vendor(self.tmp, "3.3.0")
        self.rt_root = self.tmp / "rt"
        self.copy = {
            "dir": self.vendor, "version": "3.3.0", "source": "vendor",
            "entry": self.vendor / "dpi_detector.py",
            "reqs": self.vendor / "requirements.txt",
        }

    def _menu(self, inputs, *, copy=None, latest="4.1.0", upd="4.1.0",
              install_result=(True, "/rt/4.1.0"), run_rc=0):
        """Запускает меню с патчами; возвращает (stdout, run_vendor_mock).

        Мок установки сохраняется в self.install_mock для проверок."""
        buf = io.StringIO()
        run_mock = MagicMock(return_value=run_rc)
        install_mock = MagicMock(return_value=install_result)
        self.install_mock = install_mock
        with patch.object(self.m, "_installed_copy", return_value=copy or self.copy), \
             patch.object(self.m, "_latest_upstream_version", return_value=latest), \
             patch.object(self.m, "_update_available", return_value=upd), \
             patch.object(self.m, "_download_and_install", install_mock), \
             patch.object(self.m, "_ensure_deps", return_value=True), \
             patch.object(self.m, "_run_vendor", run_mock), \
             patch("os.system", return_value=0), \
             patch("builtins.input", side_effect=inputs), \
             redirect_stdout(buf):
            self.m.do_dpi_censor_check_menu()
        return buf.getvalue(), run_mock

    def test_header_shows_installed_and_available(self):
        out, _ = self._menu(["q"])
        self.assertIn("Версия:", out)
        self.assertIn("3.3.0", out)
        self.assertIn("вендорная копия", out)
        self.assertIn("Обновление:", out)
        self.assertIn("v4.1.0", out)

    def test_header_up_to_date(self):
        out, _ = self._menu(["q"], latest="3.3.0", upd="")
        self.assertIn("последняя версия", out)

    def test_header_not_checked(self):
        out, _ = self._menu(["q"], latest="", upd="")
        self.assertIn("не проверено", out)

    def test_item4_present_in_menu(self):
        out, _ = self._menu(["q"])
        self.assertIn("[4]", out)
        self.assertIn("Обновить до v4.1.0", out)

    def test_update_offered_before_launch_default_yes(self):
        # ввод: «1» (запуск) → «y» (обновиться) → «n» (без отчёта) → Enter
        out, run_mock = self._menu(["1", "y", "n", ""])
        self.assertIn("Доступна новая версия dpi-detector", out)
        # обновление реально вызвано и запущено:
        self.install_mock.assert_called_once_with("4.1.0")
        run_mock.assert_called_once()
        args = run_mock.call_args[0][0]
        self.assertEqual(args, [])  # без доменов/прокси/вывода

    def test_update_declined_runs_current(self):
        out, run_mock = self._menu(["1", "n", "n", ""])
        self.assertIn("Доступна новая версия dpi-detector", out)
        # отказ → установка не вызывалась, тест запущен на текущей версии
        self.install_mock.assert_not_called()
        run_mock.assert_called_once()

    def test_no_update_prompt_when_current(self):
        out, run_mock = self._menu(["1", "n", ""], upd="", latest="3.3.0")
        self.assertNotIn("Доступна новая версия dpi-detector", out)
        run_mock.assert_called_once()

    def test_item4_flow_success(self):
        buf = io.StringIO()
        with patch.object(self.m, "_installed_copy", return_value=self.copy), \
             patch.object(self.m, "_latest_upstream_version", return_value="4.1.0"), \
             patch.object(self.m, "_update_available", return_value="4.1.0"), \
             patch.object(self.m, "_download_and_install",
                          return_value=(True, str(self.rt_root / "4.1.0"))), \
             patch("os.system", return_value=0), \
             patch("builtins.input", side_effect=["4", ""]), \
             redirect_stdout(buf):
            self.m.do_dpi_censor_check_menu()
        out = buf.getvalue()
        self.assertIn("Обновление dpi-detector", out)
        self.assertIn("v4.1.0", out)
        self.assertIn("Установлена версия v4.1.0", out)

    def test_item4_flow_no_update(self):
        buf = io.StringIO()
        with patch.object(self.m, "_installed_copy", return_value=self.copy), \
             patch.object(self.m, "_latest_upstream_version", return_value="3.3.0"), \
             patch.object(self.m, "_update_available", return_value=""), \
             patch("os.system", return_value=0), \
             patch("builtins.input", side_effect=["4", ""]), \
             redirect_stdout(buf):
            self.m.do_dpi_censor_check_menu()
        self.assertIn("Установлена последняя версия", buf.getvalue())

    def test_item4_flow_network_dead(self):
        buf = io.StringIO()
        with patch.object(self.m, "_installed_copy", return_value=self.copy), \
             patch.object(self.m, "_latest_upstream_version", return_value=""), \
             patch("os.system", return_value=0), \
             patch("builtins.input", side_effect=["4", ""]), \
             redirect_stdout(buf):
            self.m.do_dpi_censor_check_menu()
        out = buf.getvalue()
        self.assertIn("GitHub недоступен", out)
        self.assertIn("github.com/Runnin4ik/dpi-detector", out)

    def test_eof_on_choice_returns_quietly(self):
        buf = io.StringIO()
        with patch.object(self.m, "_installed_copy", return_value=self.copy), \
             patch.object(self.m, "_latest_upstream_version", return_value=""), \
             patch("os.system", return_value=0), \
             patch("builtins.input", side_effect=EOFError), \
             redirect_stdout(buf):
            self.m.do_dpi_censor_check_menu()  # не должно бросать

    def test_missing_tool_error_box(self):
        buf = io.StringIO()
        with patch.object(self.m, "_installed_copy", return_value={}), \
             patch("os.system", return_value=0), \
             patch("builtins.input", side_effect=[""]), \
             redirect_stdout(buf):
            self.m.do_dpi_censor_check_menu()
        out = buf.getvalue()
        self.assertIn("не найден", out)
        self.assertIn("Переустановите Химеру", out)

    def test_domains_choice_passes_args(self):
        out, run_mock = self._menu(["2", "n", "vk.com ya.ru", "n", ""])
        run_mock.assert_called_once()
        args = run_mock.call_args[0][0]
        self.assertIn("-d", args)
        self.assertIn("vk.com", args)

    def test_update_failure_falls_back_to_current(self):
        # ввод: «1» → «y» (согласие) → «n» (без отчёта) → Enter
        out, run_mock = self._menu(
            ["1", "y", "n", ""],
            install_result=(False, "не удалось скачать tarball с GitHub"),
        )
        self.assertIn("Обновление не удалось", out)
        self.assertIn("Запускаю установленную", out)
        run_mock.assert_called_once()


class TestOfferUpdateBeforeLaunch(unittest.TestCase):
    """_offer_update_before_launch — предложение обновления перед тестом."""

    def setUp(self):
        self.m = _mod()

    def test_no_update_is_noop(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.m._offer_update_before_launch("", "3.3.0")
        self.assertEqual(buf.getvalue(), "")

    def test_accept_runs_install(self):
        install = patch.object(self.m, "_download_and_install",
                               return_value=(True, "/rt/4.1.0"))
        buf = io.StringIO()
        with install, patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            self.m._offer_update_before_launch("4.1.0", "3.3.0")
        out = buf.getvalue()
        self.assertIn("v4.1.0", out)
        self.assertIn("Обновлено", out)

    def test_decline_skips_install(self):
        install = MagicMock(return_value=(True, "/rt/4.1.0"))
        buf = io.StringIO()
        with patch.object(self.m, "_download_and_install", install), \
             patch("builtins.input", return_value="n"), \
             redirect_stdout(buf):
            self.m._offer_update_before_launch("4.1.0", "3.3.0")
        self.assertEqual(install.call_count, 0)

    def test_keyboard_interrupt_skips_install(self):
        install = MagicMock(return_value=(True, "/rt/4.1.0"))
        buf = io.StringIO()
        with patch.object(self.m, "_download_and_install", install), \
             patch("builtins.input", side_effect=KeyboardInterrupt), \
             redirect_stdout(buf):
            self.m._offer_update_before_launch("4.1.0", "3.3.0")
        self.assertEqual(install.call_count, 0)


class TestCodeloadUrl(unittest.TestCase):
    """_codeload_url — URL tarball апстрима."""

    def setUp(self):
        self.m = _mod()

    def test_format(self):
        url = self.m._codeload_url("4.1.0")
        self.assertEqual(
            url,
            "https://codeload.github.com/Runnin4ik/dpi-detector/"
            "tar.gz/refs/tags/v4.1.0",
        )

    def test_v_prefix_normalized(self):
        self.assertEqual(self.m._codeload_url("v4.1.0"),
                         self.m._codeload_url("4.1.0"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
