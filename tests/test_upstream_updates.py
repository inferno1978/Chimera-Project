#!/usr/bin/env python3
"""
tests/test_upstream_updates.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/upstream_updates.py + layout-probe
функций csqtt_packages.py / wdtt_packages.py.

Покрывает:
  1. STATE: атомарный мерж, битый файл → пустой state.
  2. fetch_latest: release-тег (strip v), branch sha[:12], кэш 6 ч, force.
  3. check_target: не установлен / legacy-ревизия / доступно / актуален /
     API недоступен.
  4. update_target: отказ без бинарника; turnable скачивает ДИНАМИЧЕСКИЙ
     latest (регрессия раньше качался pinned 0.4.1).
  5. _record_installed: тот же tarball-sha → ревизия НЕ поднимается
     (CDN отдал старый архив); другой sha → поднимается.
  5b. _record_installed/record_first_install пишут в state
     номер версии (installed_version + upstream_version).
  5c. отображение версии — get_version_display,
     get_update_status_line (префикс «rev »), _fmt_target_row,
     ленивый опрос бинарника кэшируется в state.
  6. run_agent: skip неустановленных и auto=off; обновляет доступное.
  7. Layout-probe CSQTT: rust-server, csqtt-uring (легаси),
     переименованная будущая папка (rglob), клиентский крейт игнорируется.
  8. Layout-probe qWDTT: ./server, ./server.go (легаси), будущий корневой
     main.go, cmd/-конвенция, go.mod-требование.
  9. Агент-скрипт: подстановка корня репозитория в sys.path.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import upstream_updates as uu
from chimera.modules import csqtt_packages
from chimera.modules import wdtt_packages


class _TmpStateMixin:
    """Перенаправляет STATE/LOG/BIN-константы во временную директорию."""

    def setUp(self):
        super().setUp()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._orig = {
            "STATE_FILE": uu.STATE_FILE,
            "LOG_FILE": uu.LOG_FILE,
            "AGENT_BIN": uu.AGENT_BIN,
            "AGENT_SERVICE": uu.AGENT_SERVICE,
            "AGENT_TIMER": uu.AGENT_TIMER,
        }
        uu.STATE_FILE = self._tmpdir / "upstream-updates.json"
        uu.LOG_FILE = self._tmpdir / "agent.log"
        uu.AGENT_BIN = self._tmpdir / "chimera-upstream-update.py"
        uu.AGENT_SERVICE = self._tmpdir / "chimera-upstream-update.service"
        uu.AGENT_TIMER = self._tmpdir / "chimera-upstream-update.timer"

    def tearDown(self):
        import shutil
        uu.STATE_FILE = self._orig["STATE_FILE"]
        uu.LOG_FILE = self._orig["LOG_FILE"]
        uu.AGENT_BIN = self._orig["AGENT_BIN"]
        uu.AGENT_SERVICE = self._orig["AGENT_SERVICE"]
        uu.AGENT_TIMER = self._orig["AGENT_TIMER"]
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        super().tearDown()


class TestState(_TmpStateMixin, unittest.TestCase):

    def test_update_state_merge(self):
        uu.update_state("csqtt", installed_rev="abc123def456")
        uu.update_state("csqtt", latest="fff111222333", last_update="2026-09-02 12:00")
        st = uu.read_state()
        self.assertEqual(st["csqtt"]["installed_rev"], "abc123def456")
        self.assertEqual(st["csqtt"]["latest"], "fff111222333")
        # первая запись не затёрта второй
        self.assertIn("last_update", st["csqtt"])

    def test_read_state_broken_returns_empty(self):
        uu.STATE_FILE.write_text("{ not json !!!")
        self.assertEqual(uu.read_state(), {})

    def test_read_state_missing_returns_empty(self):
        self.assertEqual(uu.read_state(), {})


class TestFetchLatest(_TmpStateMixin, unittest.TestCase):

    def test_release_tag_strips_v(self):
        with patch.object(uu, "_github_api_json",
                          return_value={"tag_name": "v0.5.0"}):
            val = uu.fetch_latest("turnable", force=True)
        self.assertEqual(val, "0.5.0")

    def test_branch_sha_short(self):
        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "abcdef1234567890deadbeef"}):
            val = uu.fetch_latest("csqtt", force=True)
        self.assertEqual(val, "abcdef123456")

    def test_cache_no_second_call(self):
        calls = {"n": 0}

        def fake_api(url):
            calls["n"] += 1
            return {"sha": "1111222233334444aaaabbbb"}

        with patch.object(uu, "_github_api_json", side_effect=fake_api):
            first = uu.fetch_latest("wdtt", force=True)
            second = uu.fetch_latest("wdtt", force=False)
        self.assertEqual(first, "111122223333")
        self.assertEqual(second, first)
        self.assertEqual(calls["n"], 1)  # кэш сработал

    def test_force_bypasses_cache(self):
        calls = {"n": 0}

        def fake_api(url):
            calls["n"] += 1
            return {"sha": "1111222233334444aaaabbbb"}

        with patch.object(uu, "_github_api_json", side_effect=fake_api):
            uu.fetch_latest("wdtt", force=True)
            uu.fetch_latest("wdtt", force=True)
        self.assertEqual(calls["n"], 2)

    def test_api_none_returns_none(self):
        with patch.object(uu, "_github_api_json", return_value=None):
            self.assertIsNone(uu.fetch_latest("csqtt", force=True))


class TestCheckTarget(_TmpStateMixin, unittest.TestCase):
    """check_target на псевдо-бинарниках (без systemctl/network)."""

    def setUp(self):
        super().setUp()
        self._bin = self._tmpdir / "fake-bin"
        self._bin.write_bytes(b"\x7fELF-fake")
        self._orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        for k in uu.UPSTREAM_TARGETS:
            uu.UPSTREAM_TARGETS[k]["binary"] = self._bin

    def tearDown(self):
        uu.UPSTREAM_TARGETS.clear()
        uu.UPSTREAM_TARGETS.update(self._orig_targets)
        super().tearDown()

    def test_not_installed(self):
        uu.UPSTREAM_TARGETS["csqtt"]["binary"] = self._tmpdir / "no-such-bin"
        with patch.object(uu, "_github_api_json", return_value={"sha": "x" * 40}):
            res = uu.check_target("csqtt", force=True)
        self.assertFalse(res["update_available"])
        self.assertEqual(res["reason"], "не установлен")

    def test_release_update_available(self):
        with patch.object(uu, "_github_api_json",
                          return_value={"tag_name": "0.5.0"}), \
             patch.object(uu, "get_installed_version", return_value="0.4.1"):
            res = uu.check_target("turnable", force=True)
        self.assertTrue(res["update_available"])
        self.assertEqual(res["installed"], "0.4.1")
        self.assertEqual(res["latest"], "0.5.0")

    def test_release_actual(self):
        with patch.object(uu, "_github_api_json",
                          return_value={"tag_name": "0.4.1"}), \
             patch.object(uu, "get_installed_version", return_value="0.4.1"):
            res = uu.check_target("turnable", force=True)
        self.assertFalse(res["update_available"])

    def test_branch_legacy_no_rev(self):
        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "a" * 40}):
            res = uu.check_target("csqtt", force=True)
        self.assertFalse(res["update_available"])
        self.assertTrue(res["reason"].startswith("ревизия неизвестна"))

    def test_branch_update_available(self):
        uu.update_state("csqtt", installed_rev="old000000001")
        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "new000000002"}):
            res = uu.check_target("csqtt", force=True)
        self.assertTrue(res["update_available"])

    def test_branch_actual(self):
        sha = "abcdefabcdef" + "0" * 28          # [:12] == installed_rev
        uu.update_state("csqtt", installed_rev=sha[:12])
        with patch.object(uu, "_github_api_json", return_value={"sha": sha}):
            res = uu.check_target("csqtt", force=True)
        self.assertFalse(res["update_available"])
        self.assertEqual(res["reason"], "актуален")

    def test_api_unavailable(self):
        with patch.object(uu, "_github_api_json", return_value=None):
            res = uu.check_target("wdtt", force=True)
        self.assertFalse(res["update_available"])
        self.assertEqual(res["reason"], "GitHub API недоступен")


class TestUpdateTarget(_TmpStateMixin, unittest.TestCase):
    """Ядро fetch_package получает ДИНАМИЧЕСКУЮ версию latest."""

    def setUp(self):
        super().setUp()
        self._bin = self._tmpdir / "fake-turnable"
        self._bin.write_bytes(b"\x7fELF-fake")
        self._orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        uu.UPSTREAM_TARGETS["turnable"]["binary"] = self._bin

    def tearDown(self):
        uu.UPSTREAM_TARGETS.clear()
        uu.UPSTREAM_TARGETS.update(self._orig_targets)
        super().tearDown()

    def test_refuses_when_not_installed(self):
        uu.UPSTREAM_TARGETS["turnable"]["binary"] = self._tmpdir / "gone"
        ok = uu.update_target("turnable", interactive=False)
        self.assertFalse(ok)

    def test_turnable_fetches_dynamic_latest(self):
        """Регрессия до фикса _run_update качал pinned 0.4.1,
        обещая latest. Теперь fetch_package получает version=latest."""
        seen = {}

        def fake_fetch(spec, **kwargs):
            seen.update(kwargs)
            return True

        with patch.object(uu, "_github_api_json",
                          return_value={"tag_name": "0.6.0"}), \
             patch.object(uu, "get_installed_version", return_value="0.4.1"), \
             patch.object(uu, "_svc_active", return_value=False), \
             patch.object(uu, "_backup_binary", return_value=None), \
             patch("chimera.modules.download_manager.fetch_package",
                   side_effect=fake_fetch), \
             patch.object(uu, "_spec_for", return_value=MagicMock()):
            ok = uu.update_target("turnable", interactive=False)
        self.assertTrue(ok)
        self.assertEqual(seen.get("version"), "0.6.0")  # НЕ 0.4.1!
        # state записан
        st = uu.read_state()["turnable"]
        self.assertEqual(st["installed"], "0.4.1")  # из get_installed_version
        self.assertEqual(st["latest"], "0.6.0")

    def test_record_same_tarball_keeps_old_rev(self):
        """CDN отдал тот же архив (sha256 совпал) → ревизию не поднимаем."""
        uu.update_state("csqtt", installed_rev="oldrev00001",
                        tarball_sha256="deadbeef" * 8)
        info = {"latest": "newrev00002", "installed": "oldrev00001"}
        with patch.object(uu, "_build_info",
                          return_value={"tarball_sha256": "deadbeef" * 8}):
            uu._record_installed("csqtt", "newrev00002", info)
        st = uu.read_state()["csqtt"]
        self.assertEqual(st.get("installed_rev"), "oldrev00001")
        self.assertIn("прежний архив", st.get("last_error", ""))

    def test_record_new_tarball_bumps_rev(self):
        uu.update_state("csqtt", installed_rev="oldrev00001",
                        tarball_sha256="a" * 64)
        info = {"latest": "newrev00002", "installed": "oldrev00001"}
        with patch.object(uu, "_build_info",
                          return_value={"tarball_sha256": "b" * 64,
                                        "layout": "known:rust-server",
                                        "rust_required": "1.98.0"}):
            uu._record_installed("csqtt", "newrev00002", info)
        st = uu.read_state()["csqtt"]
        self.assertEqual(st["installed_rev"], "newrev00002")
        self.assertEqual(st["layout"], "known:rust-server")
        self.assertEqual(st["rust_required"], "1.98.0")

    def test_record_writes_installed_version(self):
        """После обновления в state лежит и НОМЕР ВЕРСИИ —
        юзеры просили явную версию, а не только sha-хэш ревизии."""
        uu.update_state("csqtt", installed_rev="oldrev00001",
                        tarball_sha256="a" * 64)
        info = {"latest": "newrev00002", "installed": "oldrev00001"}
        with patch.object(uu, "_build_info",
                          return_value={"tarball_sha256": "b" * 64,
                                        "upstream_version": "2.2.0"}), \
             patch.object(uu, "get_installed_version",
                         return_value="2.2.0"):
            uu._record_installed("csqtt", "newrev00002", info)
        st = uu.read_state()["csqtt"]
        self.assertEqual(st["installed_rev"], "newrev00002")
        self.assertEqual(st["installed_version"], "2.2.0")
        self.assertEqual(st["upstream_version"], "2.2.0")

    def test_record_version_falls_back_to_cargo(self):
        """Бинарь --version не отдал (unknown) → Cargo-версия сборки."""
        uu.update_state("csqtt", installed_rev="oldrev00001",
                        tarball_sha256="a" * 64)
        info = {"latest": "newrev00002", "installed": "oldrev00001"}
        with patch.object(uu, "_build_info",
                          return_value={"tarball_sha256": "b" * 64,
                                        "upstream_version": "2.1.9"}), \
             patch.object(uu, "get_installed_version",
                         return_value="unknown"):
            uu._record_installed("csqtt", "newrev00002", info)
        st = uu.read_state()["csqtt"]
        self.assertEqual(st["installed_version"], "2.1.9")


class TestRecordFirstInstall(_TmpStateMixin, unittest.TestCase):
    """Свежая установка СРАЗУ пишет ревизию+версию в state —
    раньше свежеустановка жила в «legacy»-режиме до первого
    ручного обновления."""

    def setUp(self):
        super().setUp()
        self._bin = self._tmpdir / "csqtt-server"
        self._bin.write_bytes(b"\x7fELF-fake")
        self._orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        uu.UPSTREAM_TARGETS["csqtt"]["binary"] = self._bin

    def tearDown(self):
        uu.UPSTREAM_TARGETS.clear()
        uu.UPSTREAM_TARGETS.update(self._orig_targets)
        super().tearDown()

    def test_source_install_records_rev_and_version(self):
        with patch.object(uu, "fetch_latest", return_value="abc123def456"), \
             patch.object(uu, "get_installed_version", return_value="2.1.9"), \
             patch.object(uu, "_build_info",
                          return_value={"tarball_sha256": "f" * 64,
                                        "layout": "known:rust-server",
                                        "upstream_version": "2.1.9"}):
            uu.record_first_install("csqtt")
        st = uu.read_state()["csqtt"]
        self.assertEqual(st["installed_rev"], "abc123def456")
        self.assertEqual(st["installed"], "abc123def456")
        self.assertEqual(st["installed_version"], "2.1.9")
        self.assertEqual(st["upstream_version"], "2.1.9")
        self.assertEqual(st["layout"], "known:rust-server")

    def test_manual_binary_records_version_but_not_rev(self):
        """Ручной бинарь: из какого коммита собран — неизвестно →
        ревизию честно НЕ пишем; версию (опрос --version) — пишем."""
        with patch.object(uu, "fetch_latest", return_value="abc123def456"), \
             patch.object(uu, "get_installed_version", return_value="2.1.9"), \
             patch.object(uu, "_build_info", return_value={}):
            uu.record_first_install("csqtt")
        st = uu.read_state()["csqtt"]
        self.assertEqual(st["installed_version"], "2.1.9")
        self.assertNotIn("installed_rev", st)
        self.assertEqual(st["latest"], "abc123def456")

    def test_offline_still_records_version(self):
        """GitHub API недоступен в момент установки — версия всё равно
        записывается (локальный опрос), ревизия — нет."""
        with patch.object(uu, "fetch_latest", return_value=None), \
             patch.object(uu, "get_installed_version", return_value="2.1.9"), \
             patch.object(uu, "_build_info", return_value={}):
            uu.record_first_install("csqtt")
        st = uu.read_state()["csqtt"]
        self.assertEqual(st["installed_version"], "2.1.9")
        self.assertNotIn("installed_rev", st)


class TestVersionDisplay(_TmpStateMixin, unittest.TestCase):
    """Номер версии — явно, хэш ревизии — с префиксом «rev »."""

    def setUp(self):
        super().setUp()
        self._bin = self._tmpdir / "csqtt-server"
        self._bin.write_bytes(b"\x7fELF-fake")
        self._orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        for k in uu.UPSTREAM_TARGETS:
            uu.UPSTREAM_TARGETS[k]["binary"] = self._bin

    def tearDown(self):
        uu.UPSTREAM_TARGETS.clear()
        uu.UPSTREAM_TARGETS.update(self._orig_targets)
        super().tearDown()

    def test_version_display_version_and_rev(self):
        uu.update_state("csqtt", installed_rev="aaa111222333",
                        installed="aaa111222333", installed_version="2.1.9")
        self.assertEqual(uu.get_version_display("csqtt"),
                         "v2.1.9 (rev aaa111222333)")

    def test_version_display_rev_only(self):
        # qWDTT: Go-бинарь не отдаёт --version → только ревизия
        uu.update_state("wdtt", installed_rev="ccc111222333",
                        installed="ccc111222333")
        self.assertEqual(uu.get_version_display("wdtt"),
                         "rev ccc111222333")

    def test_version_display_version_without_rev(self):
        # ручной бинарь: версия есть, ревизии нет
        uu.update_state("csqtt", installed_version="2.1.9")
        self.assertEqual(uu.get_version_display("csqtt"), "v2.1.9")

    def test_version_display_not_installed(self):
        uu.UPSTREAM_TARGETS["csqtt"]["binary"] = self._tmpdir / "nope"
        self.assertEqual(uu.get_version_display("csqtt"), "—")

    def test_status_line_rev_prefix_for_branch(self):
        uu.update_state("csqtt", installed="aaa111222333",
                        latest="aaa111222333")
        line = uu.get_update_status_line("csqtt")
        self.assertIn("rev aaa111222333", line)
        self.assertIn("(актуален)", line)

    def test_status_line_update_available_with_rev_prefix(self):
        uu.update_state("csqtt", installed="aaa111222333",
                        latest="bbb444555666")
        line = uu.get_update_status_line("csqtt")
        self.assertIn("rev aaa111222333 → bbb444555666 доступно", line)

    def test_status_line_release_unchanged(self):
        # turnable (release): версия и есть «установлено» — без «rev»
        uu.update_state("turnable", installed="0.4.1", latest="0.4.1")
        line = uu.get_update_status_line("turnable")
        self.assertIn("0.4.1", line)
        self.assertNotIn("rev ", line)

    def test_fmt_target_row_version_first(self):
        """Единое меню обновлений: «Установлено: v2.1.9 (rev …)»."""
        uu.update_state("csqtt", installed_rev="aaa111222333",
                        installed="aaa111222333", installed_version="2.1.9",
                        latest="aaa111222333")
        fake_info = {"update_available": False, "reason": "актуален",
                     "installed": "aaa111222333", "latest": "aaa111222333",
                     "installed_version": "2.1.9"}
        with patch.object(uu, "check_target", return_value=fake_info):
            row = uu._fmt_target_row("csqtt")
        self.assertIn("v2.1.9 (rev aaa111222333)", row)

    def test_fmt_target_row_rev_only(self):
        uu.update_state("wdtt", installed_rev="ccc111222333",
                        installed="ccc111222333", latest="ccc111222333")
        fake_info = {"update_available": False, "reason": "актуален",
                     "installed": "ccc111222333", "latest": "ccc111222333",
                     "installed_version": None}
        with patch.object(uu, "check_target", return_value=fake_info):
            row = uu._fmt_target_row("wdtt")
        self.assertIn("rev ccc111222333", row)
        self.assertNotIn("v2.1.9", row)

    def test_lazy_probe_cached_once(self):
        """Ленивый опрос бинарника (legacy-установка без версии в
        state) кэшируется — второй рендер меню не исполняет бинарь."""
        calls = {"n": 0}

        def fake_probe(key):
            calls["n"] += 1
            return "2.1.9"

        uu.update_state("csqtt", installed="aaa111222333",
                        latest="aaa111222333")
        with patch.object(uu, "get_installed_version",
                          side_effect=fake_probe):
            first = uu.get_version_display("csqtt")
            second = uu.get_version_display("csqtt")
        self.assertEqual(first, "v2.1.9 (rev aaa111222333)")
        self.assertEqual(second, first)
        self.assertEqual(calls["n"], 1)

    def test_lazy_probe_unknown_also_cached(self):
        calls = {"n": 0}

        def fake_probe(key):
            calls["n"] += 1
            return "unknown"

        uu.update_state("csqtt", installed="aaa111222333",
                        latest="aaa111222333")
        with patch.object(uu, "get_installed_version",
                          side_effect=fake_probe):
            uu.get_version_display("csqtt")
            uu.get_version_display("csqtt")
        self.assertEqual(calls["n"], 1)
        self.assertEqual(uu.read_state()["csqtt"]["installed_version"],
                         "unknown")

    def test_check_target_includes_installed_version(self):
        uu.update_state("csqtt", installed_rev="aaa111222333",
                        installed="aaa111222333", installed_version="2.1.9")
        with patch.object(uu, "_github_api_json",
                          return_value={"sha": "a" * 40}):
            res = uu.check_target("csqtt", force=True)
        self.assertEqual(res["installed_version"], "2.1.9")
        self.assertEqual(res["installed"], "aaa111222333")  # rev — как было


class TestRunAgent(_TmpStateMixin, unittest.TestCase):
    """Агент: неустановленные и auto=off пропускаются, доступное — обновляется."""

    def setUp(self):
        super().setUp()
        self._orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        # все бинарники «есть»
        for k in uu.UPSTREAM_TARGETS:
            uu.UPSTREAM_TARGETS[k]["binary"] = self._tmpdir / f"bin-{k}"
            uu.UPSTREAM_TARGETS[k]["binary"].write_bytes(b"\x7fELF")

    def tearDown(self):
        uu.UPSTREAM_TARGETS.clear()
        uu.UPSTREAM_TARGETS.update(self._orig_targets)
        super().tearDown()

    def _checks(self, results):
        """Заглушка check_target по ключу."""
        def fake_check(key, force=False):
            return results.get(key, {"update_available": False,
                                     "reason": "актуален",
                                     "installed": "x", "latest": "x"})
        return fake_check

    def test_skips_disabled_and_updates_available(self):
        uu.update_state("csqtt", auto=False)   # выключен вручную
        updated = []

        def fake_update(key, force=False, interactive=True):
            updated.append(key)
            return True

        with patch.object(uu, "check_target", side_effect=self._checks({
                "turnable": {"update_available": True, "reason": "",
                             "installed": "0.4.1", "latest": "0.5.0"}})), \
             patch.object(uu, "update_target", side_effect=fake_update):
            rc = uu.run_agent()
        self.assertEqual(updated, ["turnable"])   # csqtt (auto=off) и wdtt не тронуты
        self.assertEqual(rc, 0)

    def test_never_installs_from_scratch(self):
        uu.UPSTREAM_TARGETS["turnable"]["binary"] = self._tmpdir / "nope"
        called = []
        with patch.object(uu, "check_target", side_effect=self._checks({
                "turnable": {"update_available": True, "reason": "",
                             "installed": "0.1", "latest": "0.9"}})), \
             patch.object(uu, "update_target",
                          side_effect=lambda k, **kw: called.append(k)):
            uu.run_agent()
        self.assertNotIn("turnable", called)

    def test_error_exit_code(self):
        with patch.object(uu, "check_target", side_effect=self._checks({
                "wdtt": {"update_available": True, "reason": "",
                         "installed": "a", "latest": "b"}})), \
             patch.object(uu, "update_target", return_value=False):
            rc = uu.run_agent()
        self.assertEqual(rc, 1)


class TestCsqttLayoutProbe(unittest.TestCase):
    """_probe_csqtt_layout — три уровня + игнор клиентского крейта."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mk_tree(self, sub: str, pkg_name: str = "csqtt",
                 with_main: bool = True, root: str = "csqtt-main") -> Path:
        extract = self._tmpdir / "extract"
        pkg = extract / root
        d = pkg / sub if sub else pkg
        d.mkdir(parents=True, exist_ok=True)
        toml = f'[package]\nname = "{pkg_name}"\n'
        if with_main:
            (d / "src").mkdir(exist_ok=True)
            (d / "src" / "main.rs").write_text("fn main() {}")
        (d / "Cargo.toml").write_text(toml)
        return extract

    def test_current_rust_server_layout(self):
        extract = self._mk_tree("rust-server")
        probe = csqtt_packages._probe_csqtt_layout(extract)
        self.assertIsNotNone(probe)
        self.assertEqual(probe["how"], "known:rust-server")
        self.assertIn("csqtt", probe["bin_names"])

    def test_legacy_csqtt_uring_layout(self):
        extract = self._mk_tree("csqtt-uring")
        probe = csqtt_packages._probe_csqtt_layout(extract)
        self.assertEqual(probe["how"], "known:csqtt-uring")

    def test_future_renamed_dir_via_rglob(self):
        # никакой из известных имён — сервер называется как-то иначе
        extract = self._mk_tree("totally-new-name")
        probe = csqtt_packages._probe_csqtt_layout(extract)
        self.assertIsNotNone(probe)
        self.assertTrue(probe["how"].startswith("rglob:"))
        self.assertEqual(probe["source_dir"].name, "totally-new-name")

    def test_client_crate_not_picked_over_server(self):
        extract = self._mk_tree("server")
        # рядом лежит клиентский крейт с «клейким» именем
        client = extract / "csqtt-main" / "rust-client"
        (client / "src").mkdir(parents=True)
        (client / "src" / "main.rs").write_text("fn main() {}")
        (client / "Cargo.toml").write_text('[package]\nname = "csqtt"\n')
        probe = csqtt_packages._probe_csqtt_layout(extract)
        self.assertEqual(probe["how"], "known:server")
        self.assertEqual(probe["source_dir"].name, "server")

    def test_rust_version_parsed(self):
        extract = self._mk_tree("rust-server")
        cargo = extract / "csqtt-main" / "rust-server" / "Cargo.toml"
        cargo.write_text('[package]\nname = "csqtt"\nrust-version = "1.99.0"\n')
        probe = csqtt_packages._probe_csqtt_layout(extract)
        self.assertEqual(probe["rust_required"], "1.99.0")

    def test_package_version_parsed(self):
        """Cargo-версия крейта — из [package], НЕ из зависимостей
        (aes = "0.9.2" не должен подменить версию)."""
        extract = self._mk_tree("rust-server")
        cargo = extract / "csqtt-main" / "rust-server" / "Cargo.toml"
        cargo.write_text(
            '[package]\nname = "csqtt"\nversion = "2.1.9"\n'
            'rust-version = "1.97.1"\n\n[[bin]]\nname = "csqtt"\n\n'
            '[dependencies]\naes = "0.9.2"\nanyhow = "1.0"\n')
        probe = csqtt_packages._probe_csqtt_layout(extract)
        self.assertEqual(probe["upstream_version"], "2.1.9")

    def test_parse_cargo_toml_version_scoped_to_package(self):
        d = self._tmpdir / "crate-ver"
        d.mkdir()
        (d / "Cargo.toml").write_text(
            '[package]\nname = "csqtt"\nversion = "1.2.3"\n'
            '[dependencies]\nserde = "1.0"\n')
        info = csqtt_packages._parse_cargo_toml(d / "Cargo.toml")
        self.assertEqual(info["package_version"], "1.2.3")

    def test_parse_cargo_toml_no_version(self):
        d = self._tmpdir / "crate-nover"
        d.mkdir()
        (d / "Cargo.toml").write_text('[package]\nname = "csqtt"\n')
        info = csqtt_packages._parse_cargo_toml(d / "Cargo.toml")
        self.assertNotIn("package_version", info)

    def test_parse_cargo_toml_sections(self):
        d = self._tmpdir / "crate"
        d.mkdir()
        (d / "Cargo.toml").write_text(
            '[package]\nname = "csqtt-server"\nversion = "0.1.0"\n'
            'rust-version = "1.98.0"\n\n[[bin]]\nname = "csqtt-server"\n')
        info = csqtt_packages._parse_cargo_toml(d / "Cargo.toml")
        self.assertEqual(info["package_name"], "csqtt-server")
        self.assertEqual(info["bin_names"], ["csqtt-server"])
        self.assertEqual(info["rust_version"], "1.98.0")

    def test_no_cargo_returns_none(self):
        extract = self._tmpdir / "empty"
        extract.mkdir()
        self.assertIsNone(csqtt_packages._probe_csqtt_layout(extract))


class TestWdttLayoutProbe(unittest.TestCase):
    """_probe_wdtt_build_targets + _go_mod_requirement."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._src = self._tmpdir / "proxy-turn-vk-android-master"
        self._src.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _go_file(self, rel: str, main: bool = True):
        p = self._src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        body = "package main\n\nfunc main() {}\n" if main else "package util\n"
        p.write_text(body)
        return p

    def test_current_server_dir_layout(self):
        self._go_file("server/main.go")
        targets = wdtt_packages._probe_wdtt_build_targets(self._src)
        self.assertEqual(targets[0], "./server")

    def test_legacy_server_go_layout(self):
        self._go_file("server.go")
        targets = wdtt_packages._probe_wdtt_build_targets(self._src)
        self.assertEqual(targets[0], "./server.go")

    def test_future_root_main(self):
        # сервер вернулся в корень под новым именем main.go
        self._go_file("main.go")
        targets = wdtt_packages._probe_wdtt_build_targets(self._src)
        self.assertIn(".", targets)
        self.assertIn("./main.go", targets)

    def test_cmd_convention(self):
        self._go_file("cmd/server/main.go")
        (self._src / "go.mod").write_text("module x\n\ngo 1.25.0\n")
        targets = wdtt_packages._probe_wdtt_build_targets(self._src)
        self.assertIn("./cmd/server", targets)

    def test_no_targets_empty(self):
        # только утилитный пакет без main
        self._go_file("internal/util/thing.go", main=False)
        targets = wdtt_packages._probe_wdtt_build_targets(self._src)
        self.assertEqual(targets, [])

    def test_go_mod_requirement_parsed(self):
        (self._src / "go.mod").write_text("module x\n\ngo 1.26.1\n")
        self.assertEqual(wdtt_packages._go_mod_requirement(self._src), "1.26.1")

    def test_go_mod_requirement_default(self):
        self.assertEqual(wdtt_packages._go_mod_requirement(self._src),
                         wdtt_packages._GO_REQUIRED_DEFAULT)


class TestAgentScript(_TmpStateMixin, unittest.TestCase):

    def test_repo_root_substituted(self):
        repo_root = "/opt/vless-installer"
        script = uu.AGENT_PY_TEMPLATE.replace("__REPO_ROOT__", repo_root)
        self.assertIn(f'sys.path.insert(0, "{repo_root}")', script)
        self.assertNotIn("__REPO_ROOT__", script)
        self.assertIn("run_agent", script)

    def test_install_autoupdate_writes_artifacts(self):
        with patch.object(uu.subprocess, "run", return_value=MagicMock()) as mrun, \
             patch.object(Path, "chmod", lambda s, *a, **k: None):
            ok = uu.install_autoupdate()
        self.assertTrue(ok)
        script = uu.AGENT_BIN.read_text()
        # корень репозитория — реальный родитель этого модуля
        real_root = str(Path(uu.__file__).resolve().parents[2])
        self.assertIn(f'sys.path.insert(0, "{real_root}")', script)
        timer = uu.AGENT_TIMER.read_text()
        self.assertIn("OnCalendar=*-*-* 04:40:00", timer)
        self.assertIn("Persistent=true", timer)
        service = uu.AGENT_SERVICE.read_text()
        self.assertIn("TimeoutStartSec=3600", service)
        # systemctl вызывался: daemon-reload / enable / start
        cmds = [c.args[0][1] for c in mrun.call_args_list]
        self.assertIn("daemon-reload", cmds)


class TestTurnableMenuDelegates(unittest.TestCase):
    """Пункт 5 меню Turnable теперь открывает единое меню upstream_updates."""

    def test_run_update_delegates(self):
        sys.path.insert(0, str(_PROJECT_ROOT))
        import importlib
        turnable = importlib.import_module("chimera.modules.turnable")
        stub = MagicMock()
        recorded = {}

        def fake_menu(focus=None):
            recorded["focus"] = focus

        stub.do_upstream_update_menu = fake_menu
        with patch.dict(sys.modules,
                        {"chimera.modules.upstream_updates": stub}):
            turnable._run_update()
        self.assertEqual(recorded.get("focus"), "turnable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
