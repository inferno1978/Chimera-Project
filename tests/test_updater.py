#!/usr/bin/env python3
"""
tests/test_updater.py
──────────────────────────────────────────────────────────────────────────────
Unit-тесты модуля самообновления Chimera (chimera/modules/updater.py).

Покрывает:
  1. find_repo_root — подъём от модуля до .git, произвольная глубина,
     не-git каталог → None.
  2. tree_state — разделение tracked-правок и untracked: dirty только
     по tracked (untracked не блокируют pull --ff-only).
  3. plan_update — все вердикты: ok / up-to-date / dirty / ahead /
     detached / no-remote / not-git (порядок приоритетов: ahead важнее
     behind, dirty только при behind>0).
  4. update_info — ошибки fetch/detached/no-remote-branch; счётчики
     behind/ahead; список новых коммитов; кэш (TTL: свежий → без сети,
     протухший/refresh → fetch); запись кэша на диск.
  5. _log_subjects — парсер «sha<TAB>subject», пустой вывод, мусор.
  6. update_hint_line — локальная валидация кэша (кейс №14): валидный
     кэш (repo+HEAD совпадают, без ошибки) с behind>0 → подсказка;
     фантомные (другой путь установки, другой HEAD на диске, не-git
     установка, ошибка проверки) → None; pending_restart с несовпадающим
     _session_head → «перезапустите»; совпадение/отсутствие → None;
     кэш нечитаем → None (никаких исключений в отрисовку меню).
  7. _git_retry — ретраи только на сетевой шум (403/timeout/Connection),
     не-сетевые ошибки не ретраятся, успех с первой попытки.
  8. manage_cron — установка/снятие cron-файла, содержимое (root, --cron),
     cron_enabled.
  9. cron_tick — все SKIP-ветки (не git, detached, fetch-fail, ahead,
     up-to-date, dirty); успешный pull: HEAD меняется, pending_restart
     пишется, лог пишется; ошибочный pull: rc=1, лог ERROR, код не меняется.
 10. autocheck_enabled/set_autocheck — roundtrip через кэш-файл.
 11. start_background_check — выключенная проверка не создаёт тред;
     включённая делает fetch и не падает на ошибках; ветки без сети
     (не-git / autocheck выкл) зачищают фантомный кэш локально
     (_sanitize_stale_cache), валидный кэш не трогают.
 12. _write_cache — атомарная запись, tmp-файл не остаётся.
 13. upstream-aware fetch (кейс окт.2026 №11: локальная ветка
     chimera-v5 с upstream origin/main): upstream_branch (merge → имя,
     чужой remote игнорируется), remote_default_branch (symref-парсинг),
     _fetch_err_is_missing_ref, _fetch_origin_branch (порядок целей +
     фолбэк на дефолтную ветку только при «ветки нет», без лишнего
     ls-remote при сетевых ошибках); update_info фетчит upstream-ветку и
     пишет remote_branch/fetch_err в инфо и кэш; cron_tick тянет
     origin/<upstream> вместо локального имени.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import updater
from chimera.modules.updater import (
    find_repo_root, tree_state, plan_update, update_info,
    update_hint_line, manage_cron, cron_enabled, cron_tick,
    autocheck_enabled, set_autocheck, start_background_check,
    _log_subjects, _git_retry, _write_cache, _read_cache, _git,
)


def _cp(rc: int, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    """Заготовка результата git-команды."""
    return subprocess.CompletedProcess(["git"], returncode=rc,
                                       stdout=out, stderr=err)


class UpdaterTempBase(unittest.TestCase):
    """База: кэш/cron/лог в tmp, чтобы не трогать /var/lib и /etc."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="chimera-upd-")
        tmp = Path(self._tmp.name)
        self.cache_file = tmp / "update_check.json"
        self.cron_file  = tmp / "cron.d" / "chimera-auto-update"
        self.log_file   = tmp / "chimera-update.log"
        self.repo       = tmp / "repo"
        self.repo.mkdir(parents=True)
        self.cron_dir    = tmp / "cron.d"
        self.cron_dir.mkdir(parents=True)
        (self.repo / ".git").mkdir()
        self._saved = (updater.CACHE_FILE, updater.CRON_FILE,
                       updater.LOG_FILE)
        updater.CACHE_FILE = self.cache_file
        updater.CRON_FILE  = self.cron_file
        updater.LOG_FILE   = self.log_file
        self._saved_head = updater._session_head
        self._saved_disk = (updater._disk_head, updater._disk_head_known)

    def tearDown(self):
        updater.CACHE_FILE, updater.CRON_FILE, updater.LOG_FILE = self._saved
        updater._session_head = self._saved_head
        updater._disk_head, updater._disk_head_known = self._saved_disk
        self._tmp.cleanup()


# ── 1. find_repo_root ────────────────────────────────────────────────────────
class TestFindRepoRoot(UpdaterTempBase):

    def test_finds_git_upwards(self):
        deep = self.repo / "chimera" / "modules"
        deep.mkdir(parents=True)
        self.assertEqual(find_repo_root(deep), self.repo)

    def test_git_directory_or_file(self):
        # .git может быть файлом (worktree/submodule) — тоже репозиторий
        other = Path(tempfile.mkdtemp(prefix="chimera-wt-"))
        try:
            (other / ".git").write_text("gitdir: /somewhere\n")
            self.assertEqual(find_repo_root(other), other)
        finally:
            (other / ".git").unlink()
            other.rmdir()

    def test_no_git_returns_none(self):
        plain = Path(tempfile.mkdtemp(prefix="chimera-plain-"))
        try:
            self.assertIsNone(find_repo_root(plain))
        finally:
            plain.rmdir()

    def test_default_start_is_module_itself(self):
        # без аргумента — ищет от расположения updater.py (реальный чекаут)
        root = find_repo_root()
        self.assertTrue((root / "chimera" / "modules" / "updater.py").exists())


# ── 2. tree_state ────────────────────────────────────────────────────────────
class TestTreeState(UpdaterTempBase):

    def _patch_git(self, out: str):
        return patch.object(updater, "_git", return_value=_cp(0, out))

    def test_clean(self):
        with self._patch_git(""):
            st = tree_state(self.repo)
        self.assertFalse(st["dirty"])
        self.assertEqual(st["entries"], [])
        self.assertEqual(st["untracked"], [])

    def test_untracked_only_not_dirty(self):
        with self._patch_git("?? chimera/modules/updater.py\n"):
            st = tree_state(self.repo)
        self.assertFalse(st["dirty"])
        self.assertEqual(len(st["untracked"]), 1)
        self.assertEqual(st["entries"], [])

    def test_tracked_changes_are_dirty(self):
        with self._patch_git(" M chimera/_core.py\nM  chimera/modules/warp.py\n?? new.txt\n"):
            st = tree_state(self.repo)
        self.assertTrue(st["dirty"])
        self.assertEqual(len(st["entries"]), 2)
        self.assertEqual(len(st["untracked"]), 1)

    def test_git_error_means_clean_unknown(self):
        # git сломан → сообщаем «не dirty»: путь обновления решит сам
        with patch.object(updater, "_git", return_value=_cp(128, "", "fatal")):
            st = tree_state(self.repo)
        self.assertFalse(st["dirty"])


# ── 3. plan_update ───────────────────────────────────────────────────────────
class TestPlanUpdate(unittest.TestCase):

    def _info(self, **kw):
        base = {"error": None, "behind": 0, "ahead": 0}
        base.update(kw)
        return base

    def test_not_git(self):
        self.assertEqual(plan_update(self._info(error="not-git"), {}),
                         "not-git")

    def test_detached(self):
        self.assertEqual(plan_update(self._info(error="detached-head"), {}),
                         "detached")

    def test_fetch_failed(self):
        self.assertEqual(plan_update(self._info(error="fetch-failed"), {}),
                         "no-remote")

    def test_up_to_date(self):
        self.assertEqual(plan_update(self._info(behind=0), {}), "up-to-date")

    def test_ok_when_behind_and_clean(self):
        self.assertEqual(plan_update(self._info(behind=3), {"dirty": False}),
                         "ok")

    def test_dirty_blocks_when_behind(self):
        self.assertEqual(plan_update(self._info(behind=3), {"dirty": True}),
                         "dirty")

    def test_dirty_ignored_when_up_to_date(self):
        # behind=0 → dirty не важен, вверх приоритетнее
        self.assertEqual(plan_update(self._info(behind=0), {"dirty": True}),
                         "up-to-date")

    def test_ahead_wins_over_behind(self):
        # дивергенция: локальные коммиты → отказ, даже если есть и incoming
        self.assertEqual(plan_update(self._info(behind=2, ahead=1), {}),
                         "ahead")


# ── 4. update_info ───────────────────────────────────────────────────────────
class TestUpdateInfo(UpdaterTempBase):

    def _install_fake_git(self, mapping):
        """mapping: (первое слово args) -> CompletedProcess. Фиксируем
        последовательность вызовов fetch → rev-parse → rev-list → log."""
        calls = []

        def fake_git(args, repo, timeout=updater.GIT_TIMEOUT):
            calls.append(list(args))
            for key, cp in mapping.items():
                if args[:len(key)] == list(key):
                    return cp
            return _cp(0, "")

        return patch.object(updater, "_git", side_effect=fake_git), calls

    def test_fetch_failed_sets_error_and_writes_cache(self):
        p, _ = self._install_fake_git({("fetch",): _cp(1, "", "403")})
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "_git_retry",
                          side_effect=lambda a, r, **kw: _cp(1, "", "403")), p:
            info = update_info(refresh=True)
        self.assertEqual(info["error"], "fetch-failed")
        cache = _read_cache()
        self.assertEqual(cache.get("error"), "fetch-failed")

    def test_detached_head(self):
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value=None):
            info = update_info(refresh=True)
        self.assertEqual(info["error"], "detached-head")

    def test_no_remote_branch(self):
        p, _ = self._install_fake_git({})
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "_git_retry", return_value=_cp(0)), \
             patch.object(updater, "_head", side_effect=["abc123", None]), p:
            info = update_info(refresh=True)
        self.assertEqual(info["error"], "no-remote-branch")

    def test_behind_ahead_and_commits(self):
        p, _ = self._install_fake_git({
            ("rev-parse", "HEAD"): _cp(0, "aaa111\n"),
            ("rev-parse", "origin/chimera-v5"): _cp(0, "bbb222\n"),
            ("rev-list", "--count", "HEAD..origin/chimera-v5"): _cp(0, "2\n"),
            ("rev-list", "--count", "origin/chimera-v5..HEAD"): _cp(0, "0\n"),
            ("log",): _cp(0, "bbb222\tFIX: что-то\naaa111\tFEAT: другое\n"),
        })
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "_git_retry", return_value=_cp(0)), \
             patch.object(updater, "_head", side_effect=["aaa111", "bbb222"]), \
             patch.object(updater, "_count_between", side_effect=[2, 0]), p:
            info = update_info(refresh=True)
        self.assertIsNone(info["error"])
        self.assertEqual(info["behind"], 2)
        self.assertEqual(info["ahead"], 0)
        self.assertEqual(len(info["new_commits"]), 2)
        self.assertEqual(info["new_commits"][0][0], "bbb222")

    def test_cache_ttl_fresh_no_fetch(self):
        # свежий кэш → update_info(refresh=False) не дёргает сеть
        now = int(time.time())
        _write_cache({"repo": str(self.repo), "branch": "chimera-v5",
                      "local": "aaa", "remote": "bbb", "behind": 1,
                      "ahead": 0, "new_commits": [], "fetched_at": now,
                      "error": None})
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "_git_retry") as fetch_mock:
            info = update_info(refresh=False)
        fetch_mock.assert_not_called()
        self.assertTrue(info["cached"])
        self.assertEqual(info["behind"], 1)

    def test_cache_stale_refetches(self):
        _write_cache({"repo": str(self.repo), "fetched_at":
                      int(time.time()) - updater.CACHE_TTL - 10,
                      "behind": 99, "error": None})
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "_git_retry", return_value=_cp(0)), \
             patch.object(updater, "_head", side_effect=["x", "x"]), \
             patch.object(updater, "_count_between", side_effect=[0, 0]):
            info = update_info(refresh=False)
        self.assertFalse(info["cached"])
        self.assertEqual(info["behind"], 0)

    def test_not_git_repo(self):
        with patch.object(updater, "find_repo_root", return_value=None):
            info = update_info(refresh=True)
        self.assertEqual(info["error"], "not-git")


# ── 5. _log_subjects ─────────────────────────────────────────────────────────
class TestLogSubjects(UpdaterTempBase):

    def test_parse(self):
        with patch.object(updater, "_git",
                          return_value=_cp(0, "abc1234\tFEAT: первая\n"
                                                  "def5678\tFIX: вторая\n")):
            out = _log_subjects(self.repo, "HEAD", "origin/b")
        self.assertEqual(out, [("abc1234", "FEAT: первая"),
                               ("def5678", "FIX: вторая")])

    def test_empty_and_garbage(self):
        with patch.object(updater, "_git", return_value=_cp(0, "\n\n")):
            self.assertEqual(_log_subjects(self.repo, "a", "b"), [])
        with patch.object(updater, "_git", return_value=_cp(0, "строка без таба\n")):
            self.assertEqual(_log_subjects(self.repo, "a", "b"),
                             [("", "строка без таба")])

    def test_limit(self):
        raw = "\n".join(f"{i:07d}\tкоммит {i}" for i in range(50))
        with patch.object(updater, "_git", return_value=_cp(0, raw)):
            self.assertEqual(len(_log_subjects(self.repo, "a", "b")), 20)


# ── 6. update_hint_line ──────────────────────────────────────────────────────
class TestHintLine(UpdaterTempBase):
    """Подсказка из кэша — только после локальной валидации (кейс №14).

    Кэш живёт в /var/lib/xray-installer и переживает удаление/переустановку
    /opt/chimera — фантомные данные от прошлой установки (другой путь,
    другой HEAD, ошибка последней проверки) показывать нельзя.
    """

    def _hint(self, repo, cache, session=None, disk=None):
        """Записать кэш, выставить головы и получить подсказку.

        disk=None + disk_known=True → HEAD на диске не читается; диск-HEAD
        подставляется напрямую (без subprocess).
        """
        _write_cache(cache)
        updater._session_head = session
        updater._disk_head, updater._disk_head_known = disk, True
        with patch.object(updater, "find_repo_root", return_value=repo):
            return update_hint_line()

    def test_behind_hint_valid_cache(self):
        h = self._hint(self.repo,
                       {"behind": 4, "repo": str(self.repo), "local": "aaa111",
                        "error": None, "fetched_at": int(time.time())},
                       session="aaa111", disk="aaa111")
        self.assertIsNotNone(h)
        self.assertIn("4 коммит", h)

    def test_stale_cache_other_install_path_ignored(self):
        # кэш от другой установки (другой путь) — фантом
        h = self._hint(self.repo,
                       {"behind": 1425, "repo": "/opt/chimera",
                        "local": "aaa111", "error": None},
                       session="aaa111", disk="aaa111")
        self.assertIsNone(h)

    def test_stale_cache_same_path_other_head_ignored(self):
        # тот же путь, но HEAD на диске уже другой (переустановились) —
        # ровно сценарий «удалил папку, склонил заново — баннер остался»
        h = self._hint(self.repo,
                       {"behind": 1425, "repo": str(self.repo),
                        "local": "20d6a420e", "error": None},
                       session="b1ce093ab", disk="b1ce093ab")
        self.assertIsNone(h)

    def test_no_git_install_never_hints(self):
        # не-git установка (bootstrap-архив без .git): подсказка неактуальна
        h = self._hint(None,
                       {"behind": 1425, "repo": str(self.repo),
                        "local": "aaa111", "error": None},
                       session="aaa111", disk="aaa111")
        self.assertIsNone(h)

    def test_cache_with_error_ignored(self):
        # последняя проверка упала — данным верить нельзя
        h = self._hint(self.repo,
                       {"behind": 5, "repo": str(self.repo),
                        "local": "aaa111", "error": "fetch-failed"},
                       session="aaa111", disk="aaa111")
        self.assertIsNone(h)

    def test_disk_head_unresolvable_ignored(self):
        h = self._hint(self.repo,
                       {"behind": 5, "repo": str(self.repo),
                        "local": "aaa111", "error": None},
                       session="aaa111", disk=None)
        self.assertIsNone(h)

    def test_pending_restart_when_heads_differ(self):
        # ночной cron обновил код: диск-HEAD уже новый, сессия — на старом
        h = self._hint(self.repo,
                       {"behind": 0, "pending_restart": True, "local": "bbb222",
                        "repo": str(self.repo), "error": None},
                       session="aaa111", disk="bbb222")
        self.assertIsNotNone(h)
        self.assertIn("перезапуст", h)

    def test_pending_restart_cleared_after_restart(self):
        # TUI перезапущен на новом коде: диск == сессии
        h = self._hint(self.repo,
                       {"behind": 0, "pending_restart": True, "local": "bbb222",
                        "repo": str(self.repo), "error": None},
                       session="bbb222", disk="bbb222")
        self.assertIsNone(h)

    def test_pending_restart_ghost_ignored(self):
        # pending_restart от прошлой установки: local не совпадает с диском
        h = self._hint(self.repo,
                       {"behind": 0, "pending_restart": True, "local": "bbb222",
                        "repo": str(self.repo), "error": None},
                       session="aaa111", disk="b1ce093ab")
        self.assertIsNone(h)

    def test_fresh_state_no_hint(self):
        self.assertIsNone(update_hint_line())

    def test_broken_cache_no_exception(self):
        self.cache_file.write_text("{not json", encoding="utf-8")
        self.assertIsNone(update_hint_line())


# ── 7. _git_retry ────────────────────────────────────────────────────────────
class TestGitRetry(UpdaterTempBase):

    def test_success_first_try(self):
        seq = [_cp(0)]
        with patch.object(updater, "_git", side_effect=seq) as m:
            r = _git_retry(["fetch"], self.repo)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(m.call_count, 1)

    def test_retries_on_403_then_succeeds(self):
        seq = [_cp(1, "", "error: 403"), _cp(1, "", "error: 403"), _cp(0)]
        with patch.object(updater, "_git", side_effect=seq) as m, \
             patch.object(updater.time, "sleep"):
            r = _git_retry(["fetch"], self.repo, attempts=3)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(m.call_count, 3)

    def test_exhausted_retries(self):
        with patch.object(updater, "_git",
                          return_value=_cp(1, "", "403")) as m, \
             patch.object(updater.time, "sleep"):
            r = _git_retry(["fetch"], self.repo, attempts=3, delay=0)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(m.call_count, 3)

    def test_no_retry_on_non_network_error(self):
        # divergent branches — не сетевой шум, ретраить бессмысленно
        with patch.object(updater, "_git",
                          return_value=_cp(1, "", "Not possible to fast-forward")) as m:
            r = _git_retry(["pull"], self.repo, attempts=3, delay=0)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(m.call_count, 1)


# ── 8. manage_cron ───────────────────────────────────────────────────────────
class TestManageCron(UpdaterTempBase):

    def test_enable_writes_root_cron(self):
        self.assertTrue(manage_cron(True))
        self.assertTrue(cron_enabled())
        content = self.cron_file.read_text(encoding="utf-8")
        self.assertIn(" root ", content)
        self.assertIn("--cron", content)
        self.assertIn("30 4 * * *", content)
        self.assertIn("updater.py", content)

    def test_disable_removes(self):
        manage_cron(True)
        self.assertTrue(manage_cron(False))
        self.assertFalse(cron_enabled())

    def test_disable_without_file_ok(self):
        self.assertTrue(manage_cron(False))
        self.assertFalse(cron_enabled())


# ── 9. cron_tick ─────────────────────────────────────────────────────────────
class TestCronTick(UpdaterTempBase):

    _UNSET = object()

    def _run_tick(self, git_map=None, repo=_UNSET, branch="chimera-v5",
                  behind=0, ahead=0, dirty=False, pull_rc=0,
                  head_seq=None, fetch_rc=0):
        """Обезьянка вокруг cron_tick: подменяем git-слой целиком."""
        head_seq = head_seq or ["aaa111", "bbb222"]

        def fake_git(args, r, timeout=updater.GIT_TIMEOUT):
            a = list(args)
            if a[0] == "fetch":
                return _cp(fetch_rc, "", "403" if fetch_rc else "")
            if a[0] == "rev-parse" and len(a) >= 3 and a[1] == "--abbrev-ref":
                return _cp(0, branch + "\n") if branch else _cp(1)
            if a[0] == "rev-parse":
                return _cp(0, head_seq.pop(0) + "\n") if head_seq else _cp(1)
            if a[0] == "rev-list":
                # HEAD..origin → behind; origin..HEAD → ahead
                return _cp(0, f"{behind if '..o' in ' '.join(a) or 'origin' in a[-1] and a[-2] == 'HEAD..origin/' + branch else ahead}\n")
            if a[0] == "status":
                return _cp(0, " M f.py\n" if dirty else "")
            if a[0] == "pull":
                return _cp(pull_rc, "", "" if pull_rc == 0 else "divergent")
            return _cp(0, "")

        with patch.object(updater, "find_repo_root",
                          return_value=(self.repo if repo is self._UNSET else repo)), \
             patch.object(updater, "_git", side_effect=fake_git), \
             patch.object(updater, "_git_retry",
                          side_effect=lambda a, r, **kw: fake_git(a, r)):
            rc = cron_tick()
        return rc

    def test_skip_not_git(self):
        self.assertEqual(self._run_tick(repo=None), 0)
        self.assertIn("SKIP: не git", self.log_file.read_text(encoding="utf-8"))

    def test_skip_detached(self):
        self.assertEqual(self._run_tick(branch=None), 0)
        self.assertIn("detached", self.log_file.read_text(encoding="utf-8"))

    def test_skip_fetch_failed(self):
        self.assertEqual(self._run_tick(fetch_rc=1), 0)
        self.assertIn("fetch не удался", self.log_file.read_text(encoding="utf-8"))

    def test_skip_ahead(self):
        self.assertEqual(self._run_tick(behind=2, ahead=1), 0)
        self.assertIn("опережает", self.log_file.read_text(encoding="utf-8"))

    def test_skip_up_to_date(self):
        self.assertEqual(self._run_tick(behind=0), 0)
        self.assertIn("обновлений нет", self.log_file.read_text(encoding="utf-8"))

    def test_skip_dirty(self):
        self.assertEqual(self._run_tick(behind=2, dirty=True), 0)
        self.assertIn("грязное", self.log_file.read_text(encoding="utf-8"))
        # код не тронут: pending_restart не писался
        self.assertFalse(_read_cache().get("pending_restart"))

    def test_success_pull(self):
        rc = self._run_tick(behind=1, ahead=0)
        self.assertEqual(rc, 0)
        log = self.log_file.read_text(encoding="utf-8")
        self.assertIn("OK: обновлён", log)
        cache = _read_cache()
        self.assertTrue(cache.get("pending_restart"))
        self.assertEqual(cache.get("behind"), 0)
        self.assertEqual(cache.get("branch"), "chimera-v5")

    def test_pull_error_logged_and_rc1(self):
        rc = self._run_tick(behind=1, pull_rc=1)
        self.assertEqual(rc, 1)
        log = self.log_file.read_text(encoding="utf-8")
        self.assertIn("ERROR: pull", log)
        # код не поменялся → pending_restart не пишется
        self.assertFalse(_read_cache().get("pending_restart"))


# ── 10. autocheck ────────────────────────────────────────────────────────────
class TestAutocheck(UpdaterTempBase):

    def test_default_on(self):
        self.assertTrue(autocheck_enabled())

    def test_roundtrip(self):
        set_autocheck(False)
        self.assertFalse(autocheck_enabled())
        set_autocheck(True)
        self.assertTrue(autocheck_enabled())

    def test_does_not_clobber_other_keys(self):
        _write_cache({"behind": 7, "pending_restart": True})
        set_autocheck(False)
        cache = _read_cache()
        self.assertEqual(cache.get("behind"), 7)
        self.assertTrue(cache.get("pending_restart"))
        self.assertFalse(cache.get("autocheck"))


# ── 11. start_background_check ───────────────────────────────────────────────
class TestBackgroundCheck(UpdaterTempBase):

    def test_disabled_no_thread(self):
        set_autocheck(False)
        with patch.object(updater, "update_info") as ui:
            start_background_check()
            time.sleep(0.05)
            ui.assert_not_called()

    def test_enabled_runs_and_swallows_errors(self):
        set_autocheck(True)
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "update_info",
                          side_effect=RuntimeError("boom")) as ui:
            start_background_check()
            time.sleep(0.2)     # даём daemon-треду отработать
            ui.assert_called_once_with(refresh=True)   # исключение проглочено

    def test_no_git_sanitize_phantom_cache(self):
        # не-git установка: фантомный кэш от прошлой git-установки зачищается
        # без сети (настройка autocheck сохраняется)
        _write_cache({"behind": 1425, "ahead": 541, "repo": "/opt/chimera",
                      "local": "20d6a420e", "pending_restart": True,
                      "new_commits": [("x", "y")], "autocheck": True,
                      "fetched_at": 1, "error": None})
        with patch.object(updater, "find_repo_root", return_value=None):
            start_background_check()
        cache = _read_cache()
        self.assertEqual(cache.get("behind"), 0)
        self.assertEqual(cache.get("ahead"), 0)
        self.assertEqual(cache.get("new_commits"), [])
        self.assertFalse(cache.get("pending_restart"))
        self.assertTrue(cache.get("autocheck"))    # настройка не тронута

    def test_autocheck_off_sanitize_phantom_cache(self):
        # проверка выключена пользователем: refresh-а не будет — чистим фантом
        set_autocheck(False)
        _write_cache({"behind": 1425, "repo": str(self.repo),
                      "local": "20d6a420e", "autocheck": False,
                      "fetched_at": 1, "error": None})
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "_head", return_value="b1ce093ab"):
            start_background_check()
        self.assertEqual(_read_cache().get("behind"), 0)

    def test_autocheck_off_valid_cache_preserved(self):
        # ручная проверка (U→1) уже записала актуальные данные — не трогаем:
        # HEAD сессии совпадает с кэшем, это честный результат для юзера
        set_autocheck(False)
        _write_cache({"behind": 5, "repo": str(self.repo), "local": "aaa111",
                      "autocheck": False, "error": None,
                      "fetched_at": int(time.time())})
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "_head", return_value="aaa111"):
            start_background_check()
        self.assertEqual(_read_cache().get("behind"), 5)


# ── 12. _write_cache ─────────────────────────────────────────────────────────
class TestWriteCache(UpdaterTempBase):

    def test_atomic_no_tmp_left(self):
        _write_cache({"behind": 1})
        self.assertTrue(self.cache_file.exists())
        self.assertFalse(self.cache_file.with_suffix(".json.tmp").exists())
        self.assertEqual(_read_cache()["behind"], 1)

    def test_unicode_roundtrip(self):
        _write_cache({"branch": "chimera-v5", "note": "ночной апдейт ✓"})
        self.assertEqual(_read_cache()["note"], "ночной апдейт ✓")


# ── 13. upstream-aware fetch (кейс окт.2026 №11: chimera-v5 → origin/main) ──
class TestUpstreamBranch(UpdaterTempBase):
    """upstream_branch: branch.<B>.merge → имя ветки на origin."""

    def _cfg(self, remote=None, merge=None):
        def fake_git(args, repo, timeout=updater.GIT_TIMEOUT):
            a = list(args)
            if a[:3] == ["config", "--get", "branch.chimera-v5.remote"]:
                return _cp(0, remote + "\n") if remote else _cp(1)
            if a[:3] == ["config", "--get", "branch.chimera-v5.merge"]:
                return _cp(0, merge + "\n") if merge else _cp(1)
            return _cp(0, "")
        return patch.object(updater, "_git", side_effect=fake_git)

    def test_origin_upstream_stripped(self):
        # refs/heads/main → main
        with self._cfg(remote="origin", merge="refs/heads/main"):
            self.assertEqual(updater.upstream_branch(self.repo, "chimera-v5"),
                             "main")

    def test_upstream_in_other_remote_ignored(self):
        # upstream смотрит в github-зеркало → для origin-фетча не используется
        with self._cfg(remote="github", merge="refs/heads/chimera-v5"):
            self.assertIsNone(updater.upstream_branch(self.repo, "chimera-v5"))

    def test_no_upstream_config(self):
        with self._cfg():
            self.assertIsNone(updater.upstream_branch(self.repo, "chimera-v5"))

    def test_merge_without_refprefix(self):
        with self._cfg(remote="origin", merge="main"):
            self.assertEqual(updater.upstream_branch(self.repo, "chimera-v5"),
                             "main")


class TestRemoteDefaultBranch(UpdaterTempBase):
    """remote_default_branch: ls-remote --symref origin HEAD → main."""

    def test_parse_symref_line(self):
        cp = _cp(0, "ref: refs/heads/main\tHEAD\n"
                    "380b51846017775da8c845e869e77ab56e838d7e\tHEAD\n")
        with patch.object(updater, "_git", return_value=cp):
            self.assertEqual(updater.remote_default_branch(self.repo), "main")

    def test_no_symref_line(self):
        with patch.object(updater, "_git", return_value=_cp(0, "sha\tHEAD\n")):
            self.assertIsNone(updater.remote_default_branch(self.repo))

    def test_git_error(self):
        with patch.object(updater, "_git", return_value=_cp(128, "", "fatal")):
            self.assertIsNone(updater.remote_default_branch(self.repo))


class TestMissingRefErr(UpdaterTempBase):

    def test_missing_ref_variants(self):
        self.assertTrue(updater._fetch_err_is_missing_ref(
            "fatal: couldn't find remote ref chimera-v5"))
        self.assertTrue(updater._fetch_err_is_missing_ref(
            "fatal: could not find remote branch chimera-v5"))

    def test_network_and_empty_not_missing(self):
        self.assertFalse(updater._fetch_err_is_missing_ref(
            "error: RPC failed; HTTP 403 curl 22"))
        self.assertFalse(updater._fetch_err_is_missing_ref(
            "Failed to connect: timed out"))
        self.assertFalse(updater._fetch_err_is_missing_ref(""))


class TestFetchOriginBranch(UpdaterTempBase):

    def test_fetches_upstream_branch(self):
        # локальная chimera-v5 → фетчим origin/main, а не локальное имя
        with patch.object(updater, "upstream_branch", return_value="main"), \
             patch.object(updater, "_git_retry", return_value=_cp(0)) as m:
            r, name = updater._fetch_origin_branch(self.repo, "chimera-v5")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(name, "main")
        m.assert_called_once_with(["fetch", "--quiet", "origin", "main"],
                                  self.repo, timeout=updater.FETCH_TIMEOUT)

    def test_fallback_to_default_branch(self):
        # локального имени на origin нет → ls-remote HEAD → фетчим main
        fetches = [_cp(1, "", "fatal: couldn't find remote ref chimera-v5"),
                   _cp(0)]

        def fake_retry(args, repo, timeout=None, **kw):
            return fetches.pop(0)

        with patch.object(updater, "upstream_branch", return_value=None), \
             patch.object(updater, "_git_retry", side_effect=fake_retry), \
             patch.object(updater, "remote_default_branch",
                          return_value="main") as dflt:
            r, name = updater._fetch_origin_branch(self.repo, "chimera-v5")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(name, "main")
        dflt.assert_called_once_with(self.repo)

    def test_network_error_no_fallback(self):
        # сетевая ошибка — ls-remote не дёргается (фолбэк не для сети)
        with patch.object(updater, "upstream_branch", return_value=None), \
             patch.object(updater, "_git_retry",
                          return_value=_cp(1, "", "HTTP 403")) as m, \
             patch.object(updater, "remote_default_branch") as dflt:
            r, name = updater._fetch_origin_branch(self.repo, "chimera-v5")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(name, "chimera-v5")
        self.assertEqual(m.call_count, 1)
        dflt.assert_not_called()

    def test_fallback_skipped_when_default_equals_local(self):
        # дефолтная ветка совпала с локальным именем — второй fetch не нужен
        with patch.object(updater, "upstream_branch", return_value=None), \
             patch.object(updater, "_git_retry",
                          return_value=_cp(1, "",
                                           "fatal: couldn't find remote ref v9")) as m, \
             patch.object(updater, "remote_default_branch", return_value="v9"):
            r, name = updater._fetch_origin_branch(self.repo, "v9")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(m.call_count, 1)


class TestUpstreamAwareUpdateInfo(UpdaterTempBase):
    """Живой кейс окт.2026 №11: ветка chimera-v5, upstream — origin/main."""

    def test_update_info_uses_upstream(self):
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "upstream_branch", return_value="main"), \
             patch.object(updater, "_git_retry", return_value=_cp(0)) as m, \
             patch.object(updater, "_head",
                          side_effect=["aaa111", "bbb222"]), \
             patch.object(updater, "_count_between", side_effect=[2, 0]), \
             patch.object(updater, "_log_subjects", return_value=[]):
            info = update_info(refresh=True)
        self.assertIsNone(info["error"])
        self.assertEqual(info["remote_branch"], "main")
        self.assertEqual(m.call_args[0][0],
                         ["fetch", "--quiet", "origin", "main"])
        self.assertEqual(info["behind"], 2)
        self.assertEqual(_read_cache().get("remote_branch"), "main")

    def test_fetch_err_recorded(self):
        # при падении fetch текст ошибки git попадает в инфо и кэш —
        # меню показывает его вместо дезинформирующего «сеть/CF»
        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "upstream_branch", return_value="main"), \
             patch.object(updater, "_git_retry",
                          return_value=_cp(1, "", "error: HTTP 403")):
            info = update_info(refresh=True)
        self.assertEqual(info["error"], "fetch-failed")
        self.assertEqual(info["fetch_err"], "error: HTTP 403")
        self.assertEqual(_read_cache().get("fetch_err"), "error: HTTP 403")

    def test_fallback_when_local_name_absent_on_origin(self):
        # upstream не настроен, локального имени на origin нет → main по HEAD
        def fake_retry(args, repo, timeout=None, **kw):
            if args[-1] == "chimera-v5":
                return _cp(1, "", "fatal: couldn't find remote ref chimera-v5")
            return _cp(0)

        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "upstream_branch", return_value=None), \
             patch.object(updater, "_git_retry", side_effect=fake_retry), \
             patch.object(updater, "remote_default_branch", return_value="main"), \
             patch.object(updater, "_head",
                          side_effect=["aaa111", "bbb222"]), \
             patch.object(updater, "_count_between", side_effect=[0, 0]):
            info = update_info(refresh=True)
        self.assertIsNone(info["error"])
        self.assertEqual(info["remote_branch"], "main")
        self.assertEqual(info["behind"], 0)


class TestCronUpstreamAware(UpdaterTempBase):

    def test_cron_pulls_upstream_branch(self):
        calls = []

        def fake_retry(args, repo, timeout=None, **kw):
            calls.append(list(args))
            return _cp(0)

        with patch.object(updater, "find_repo_root", return_value=self.repo), \
             patch.object(updater, "current_branch", return_value="chimera-v5"), \
             patch.object(updater, "upstream_branch", return_value="main"), \
             patch.object(updater, "_git_retry", side_effect=fake_retry), \
             patch.object(updater, "_head",
                          side_effect=["bbb222", "aaa111", "ccc333"]), \
             patch.object(updater, "_count_between", side_effect=[1, 0]), \
             patch.object(updater, "tree_state", return_value={"dirty": False}):
            rc = cron_tick()
        self.assertEqual(rc, 0)
        self.assertIn(["fetch", "--quiet", "origin", "main"], calls)
        self.assertIn(["pull", "--ff-only", "--quiet", "origin", "main"], calls)
        self.assertIn("OK: обновлён", self.log_file.read_text(encoding="utf-8"))
        self.assertEqual(_read_cache().get("remote_branch"), "main")


if __name__ == "__main__":
    unittest.main(verbosity=2)
