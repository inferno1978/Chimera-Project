# tests/test_env_isolation.py
"""
Самопроверка env-изоляции (tests/_env_isolation.py) — гард группы 8
«Инфраструктура». Все проверки идут в ПОДПРОЦЕССАХ с фейковым префиксом
(CHIMERA_TEST_ISOLATE_PREFIXES): тесты не зависят от того, существует ли
прод-дерево на стенде (песочница/GHA/раннер на живой ноде), и не трогают
реальные пути.

ЧТО ПРОВЕРЯЕТСЯ:
  1. Без CHIMERA_TEST_ISOLATE=1 install() — no-op, пути видимы.
  2. С изоляцией: stat/lstat/access/open(io+builtins)/scandir/listdir/
     unlink/rename для путей под префиксом ведут себя как «пути нет»
     (ENOENT / False) — pathlib.Path.exists/read_text/unlink included.
  3. shutil.which не находит бинаррь под префиксом (os.access → False).
  4. sitecustomize (tests/_ci_site) активирует изоляцию в сабпроцессах.
  5. Границы: сам префикс и дети изолированы, соседние пути — нет.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestEnvIsolation(unittest.TestCase):

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="envisol_"))
        # фейковое «прод-дерево»: файл + каталог + бинаррь
        self._prod = self._tmp / "fakeprod"
        (self._prod / "sub").mkdir(parents=True)
        self._file = self._prod / "state.json"
        self._file.write_text('{"installed": true}')
        self._bin = self._prod / "xraybin"
        self._bin.write_text("#!/bin/sh\nexit 0\n")
        self._bin.chmod(0o755)
        # сосед (вне префикса) — должен остаться видимым
        self._sibling = self._tmp / "sibling.txt"
        self._sibling.write_text("visible")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    # ── хелперы ────────────────────────────────────────────────────────────
    def _run(self, code, isolate=True, extra_env=None):
        """Сабпроцесс с чистым интерпретатором; код исполняется после
        install(). Возвращает (rc, stdout+stderr)."""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        if isolate:
            env["CHIMERA_TEST_ISOLATE"] = "1"
            env["CHIMERA_TEST_ISOLATE_PREFIXES"] = str(self._prod)
        else:
            env.pop("CHIMERA_TEST_ISOLATE", None)
            env.pop("CHIMERA_TEST_ISOLATE_PREFIXES", None)
        if extra_env:
            env.update(extra_env)
        wrapper = (
            "import os, sys\n"
            "from tests._env_isolation import install\n"
            "installed = install()\n"
            "print('INSTALLED', installed)\n"
            + code
        )
        r = subprocess.run([sys.executable, "-c", wrapper],
                           capture_output=True, text=True, env=env,
                           cwd=str(REPO_ROOT), timeout=60)
        return r.returncode, r.stdout + r.stderr

    # ── 1. без env-переменной — no-op ─────────────────────────────────────
    def test_noop_without_env_var(self):
        code = (
            f"import pathlib\n"
            f"assert install() is False\n"
            f"assert pathlib.Path({str(self._file)!r}).exists(), 'без изоляции путь видим'\n"
            f"print('OK-VISIBLE')\n"
        )
        rc, out = self._run(code, isolate=False)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-VISIBLE", out)

    def test_install_returns_true_with_env_var(self):
        rc, out = self._run("print('DONE')\n")
        self.assertEqual(rc, 0, out)
        self.assertIn("INSTALLED True", out)

    def test_idempotent_double_install(self):
        code = (
            "assert install() is True  # второй вызов — no-op, но True\n"
            "print('OK-IDEMPOTENT')\n"
        )
        rc, out = self._run(code)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-IDEMPOTENT", out)

    # ── 2. семейство stat ──────────────────────────────────────────────────
    def test_stat_family_invisible(self):
        code = (
            "import os, pathlib\n"
            f"p = pathlib.Path({str(self._file)!r})\n"
            "assert not p.exists(), 'exists() должен быть False'\n"
            "assert not p.is_file(), 'is_file() должен быть False'\n"
            "assert not os.path.exists(str(p)), 'os.path.exists'\n"
            "assert not os.path.isfile(str(p)), 'os.path.isfile'\n"
            "assert not os.path.isdir(str(p.parent)), 'os.path.isdir'\n"
            "try:\n"
            "    os.stat(str(p)); raise SystemExit('stat должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "try:\n"
            "    os.lstat(str(p)); raise SystemExit('lstat должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "print('OK-STAT')\n"
        )
        rc, out = self._run(code)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-STAT", out)

    # ── 3. open (io.open + builtins.open + os.open) ────────────────────────
    def test_open_invisible_read_and_write(self):
        code = (
            "import io, os, pathlib\n"
            f"p = {str(self._file)!r}\n"
            "for opener in (open, io.open):\n"
            "    try:\n"
            "        opener(p); raise SystemExit('open(r) должен кинуть ENOENT')\n"
            "    except FileNotFoundError:\n"
            "        pass\n"
            "try:\n"
            "    open(p, 'w'); raise SystemExit('open(w) должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "try:\n"
            "    os.open(p, os.O_RDONLY); raise SystemExit('os.open должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            f"path_p = pathlib.Path(p)\n"
            "try:\n"
            "    path_p.read_text(); raise SystemExit('read_text должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "try:\n"
            "    path_p.write_text('x'); raise SystemExit('write_text должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "print('OK-OPEN')\n"
        )
        rc, out = self._run(code)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-OPEN", out)
        # реальный файл НЕ тронут изоляцией write_text (мы его «не видим»)
        self.assertEqual(self._file.read_text(), '{"installed": true}')

    # ── 4. unlink / rename / scandir ──────────────────────────────────────
    def test_mutations_invisible(self):
        code = (
            "import os, pathlib\n"
            f"p = pathlib.Path({str(self._file)!r})\n"
            "try:\n"
            "    p.unlink(); raise SystemExit('unlink должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "try:\n"
            "    os.remove(str(p)); raise SystemExit('os.remove должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            f"tmp_src = {str(self._tmp / 'src.txt')!r}\n"
            "open(tmp_src, 'w').write('s')\n"
            f"dst = {str(self._prod / 'moved.txt')!r}\n"
            "try:\n"
            "    os.rename(tmp_src, dst); raise SystemExit('rename в изоляцию должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            f"d = {str(self._prod)!r}\n"
            "try:\n"
            "    os.scandir(d); raise SystemExit('scandir должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "try:\n"
            "    os.listdir(d); raise SystemExit('listdir должен кинуть ENOENT')\n"
            "except FileNotFoundError:\n"
            "    pass\n"
            "print('OK-MUT')\n"
        )
        rc, out = self._run(code)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-MUT", out)
        # реальный файл уцелел (unlink был «невидимым»)
        self.assertTrue(self._file.exists())

    # ── 5. os.access → shutil.which ───────────────────────────────────────
    def test_access_false_which_none(self):
        code = (
            "import os, shutil\n"
            f"b = {str(self._bin)!r}\n"
            "assert os.access(b, os.X_OK) is False, 'access(X_OK) должен быть False'\n"
            "assert os.access(b, os.R_OK) is False\n"
            "old_path = os.environ.get('PATH', '')\n"
            "os.environ['PATH'] = os.path.dirname(b) + os.pathsep + old_path\n"
            "w = shutil.which('xraybin')\n"
            "assert w is None, f'which должен вернуть None, получил {w!r}'\n"
            "print('OK-ACCESS')\n"
        )
        rc, out = self._run(code)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-ACCESS", out)

    # ── 6. границы префикса ───────────────────────────────────────────────
    def test_sibling_paths_not_isolated(self):
        code = (
            "import pathlib\n"
            f"s = pathlib.Path({str(self._sibling)!r})\n"
            "assert s.exists(), 'соседний путь вне префикса должен быть видим'\n"
            "assert s.read_text() == 'visible'\n"
            f"prod_root = pathlib.Path({str(self._prod)!r})\n"
            "assert not prod_root.exists(), 'сам префикс должен быть невидим'\n"
            "assert not (prod_root / 'sub').exists(), 'дети префикса невидимы'\n"
            "print('OK-BOUNDARY')\n"
        )
        rc, out = self._run(code)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-BOUNDARY", out)

    # ── 7. sitecustomize в сабпроцессе ────────────────────────────────────
    def test_sitecustomize_activates_isolation_in_subprocess(self):
        """Схема CI: PYTHONPATH=репо:tests/_ci_site + env var → сайт-хук
        ставит изоляцию БЕЗ явного import tests в коде сабпроцесса."""
        code = (
            "import os, pathlib\n"
            "assert os.environ.get('CHIMERA_TEST_ISOLATE') == '1'\n"
            "# sitecustomize уже отработал: прод-файл невидим\n"
            f"assert not pathlib.Path({str(self._file)!r}).exists(), \\\n"
            "    'sitecustomize должен был поставить изоляцию'\n"
            "from tests._env_isolation import is_active\n"
            "assert is_active(), 'is_active() должен быть True'\n"
            "print('OK-SITE')\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + str(REPO_ROOT / "tests" / "_ci_site")
        env["CHIMERA_TEST_ISOLATE"] = "1"
        env["CHIMERA_TEST_ISOLATE_PREFIXES"] = str(self._prod)
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True, env=env,
                           cwd=str(REPO_ROOT), timeout=60)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("OK-SITE", out)

    # ── 8. дефолтные префиксы не переопределены в CI ──────────────────────
    def test_default_prefixes_when_no_override(self):
        """Без CHIMERA_TEST_ISOLATE_PREFIXES изоляция использует дефолтный
        список прод-деревьев (смоук: /var/lib/xray-installer в нём)."""
        code = (
            "from tests._env_isolation import _DEFAULT_PREFIXES\n"
            "assert '/var/lib/xray-installer' in _DEFAULT_PREFIXES\n"
            "assert '/etc/xray' in _DEFAULT_PREFIXES\n"
            "assert '/opt/chimera' in _DEFAULT_PREFIXES\n"
            "print('OK-DEFAULTS')\n"
        )
        env = dict(os.environ)
        env.pop("CHIMERA_TEST_ISOLATE_PREFIXES", None)
        rc, out = self._run(code, extra_env={"CHIMERA_TEST_ISOLATE_PREFIXES": ""})
        self.assertEqual(rc, 0, out)
        self.assertIn("OK-DEFAULTS", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
